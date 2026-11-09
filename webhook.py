"""
ScamCheck Ghana — WhatsApp bot webhook.

Receives messages from Meta's WhatsApp Cloud API and walks users through
checking and reporting scam phone numbers, using the schema in schema.sql.

Flow:
  idle --(sends a number)--> check the number
  idle --("REPORT")--> awaiting_number --> awaiting_scam_type
                     --> awaiting_description (only if "something else")
  idle --("DISPUTE")--> awaiting_dispute

Run:  python webhook.py   (needs the env vars listed in README.md)
"""

import os
import re
from datetime import datetime, timezone

import psycopg2
import requests
from flask import Flask, jsonify, request
from psycopg2.extras import Json, RealDictCursor

app = Flask(__name__)

# --- Config (all from environment, never hardcoded) ---
VERIFY_TOKEN = os.environ["VERIFY_TOKEN"]        # you invent this string
WHATSAPP_TOKEN = os.environ["WHATSAPP_TOKEN"]    # from Meta dashboard
PHONE_NUMBER_ID = os.environ["PHONE_NUMBER_ID"]  # your bot's number id
DATABASE_URL = os.environ["DATABASE_URL"]        # Supabase connection string
GRAPH_VERSION = os.environ.get("GRAPH_VERSION", "v21.0")
API_URL = f"https://graph.facebook.com/{GRAPH_VERSION}/{PHONE_NUMBER_ID}/messages"

SCAM_LABELS = {
    "fake_agent": "fake MTN agent",
    "wrong_number": "'wrong number, I sent you money' trick",
    "prize_scam": "prize / lottery scam",
    "other": "other scam",
}

MENU = (
    "👋 Welcome to *ScamCheck Ghana*! Send me any suspicious phone number "
    "and I'll tell you if it's been reported for fraud.\n\n"
    "1️⃣ CHECK — look up a number\n"
    "2️⃣ REPORT — report a scam number\n"
    "3️⃣ HELP — how this works"
)

HELP_TEXT = (
    "ScamCheck Ghana is a community fraud directory. Reports come from "
    "everyday users — they're *not* verified by MTN or the police, so stay alert. "
    "3+ unique reports = flagged. Number flagged unfairly? Reply DISPUTE."
)

# Ghana mobile network prefixes (the two digits after the leading 0)
GH_PREFIXES = {"20", "23", "24", "25", "26", "27", "28", "29",
               "50", "53", "54", "55", "56", "57", "59"}


# --- Database helpers ---
def db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    conn.autocommit = True
    return conn


def get_user(wa_id):
    """Fetch/create a user; record current processing activity on every text contact."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("select * from users where whatsapp_id = %s", (wa_id,))
        user = cur.fetchone()
        if user:
            cur.execute(
                "update users set last_seen_at = greatest(last_seen_at, clock_timestamp()) where id = %s",
                (user["id"],))
        else:
            cur.execute(
                "insert into users (whatsapp_id) values (%s) returning *",
                (wa_id,))
            user = cur.fetchone()
    return user


def set_state(user_id, state, state_data=None):
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "update users set state = %s, state_data = %s where id = %s",
            (state, Json(state_data or {}), user_id))


# --- WhatsApp sending ---
def send_text(to, body):
    """Attempt once. Log safe failure categories; never log payloads or credentials.

    A true result means Graph accepted the request, not WhatsApp delivery.
    Do not raise to the webhook or retry here: the request may already be sent.
    """
    try:
        response = requests.post(
            API_URL,
            headers={"Authorization": f"Bearer {WHATSAPP_TOKEN}"},
            json={"messaging_product": "whatsapp",
                  "to": to,
                  "type": "text",
                  "text": {"body": body}},
            timeout=15,
        )
    except requests.RequestException:
        # A timeout can have an unknown send outcome. Never log exception text.
        app.logger.error("whatsapp_send_failed reason=transport outcome=unknown")
        return False

    if not 200 <= response.status_code < 300:
        # Do not log Graph bodies: they may contain message/recipient details.
        app.logger.error("whatsapp_send_failed reason=http status=%s",
                         response.status_code)
        return False
    try:
        result = response.json()
    except ValueError:
        app.logger.error("whatsapp_send_failed reason=invalid_json")
        return False
    if (not isinstance(result, dict) or result.get("error")
            or not isinstance(result.get("messages"), list)
            or not any(isinstance(message, dict) and message.get("id")
                       for message in result["messages"])):
        app.logger.error("whatsapp_send_failed reason=unexpected_response")
        return False
    return True


# --- Phone number handling ---
def normalize_ghana_number(raw):
    """'055 123 4567' / '+233551234567' -> '233551234567'. None if invalid."""
    digits = re.sub(r"\D", "", raw or "")
    if digits.startswith("233") and len(digits) == 12:
        canonical = digits
    elif digits.startswith("0") and len(digits) == 10:
        canonical = "233" + digits[1:]
    else:
        return None
    if canonical[3:5] not in GH_PREFIXES:
        return None
    return canonical


def display_number(canonical):
    """'233551234567' -> '0551234567' (the form users recognise)."""
    return "0" + canonical[3:]


def extract_number(text):
    """Find the first thing that looks like a Ghana number inside free text."""
    m = re.search(r"(?<!\d)(?:\+?233\d{9}|0\d{9})(?!\d)", text or "")
    return normalize_ghana_number(m.group(0)) if m else None


# --- Core flows ---
def handle_check(wa_id, canonical):
    disp = display_number(canonical)
    with db() as conn, conn.cursor() as cur:
        cur.execute("select * from phone_numbers where number = %s", (canonical,))
        row = cur.fetchone()
        # Read stored reports, not the cached risk label: one/two reports can
        # legitimately coexist with risk_status='clean'. Do not call that safe.
        reporters = 0
        if row:
            cur.execute(
                "select count(distinct reporter_id) as n from reports "
                "where phone_number_id = %s and cycle = %s",
                (row["id"], row["flag_cycle"]))
            reporters = cur.fetchone()["n"]
        if reporters:
            cur.execute(
                """select scam_type, count(*) as n from reports
                   where phone_number_id = %s and cycle = %s
                   group by scam_type order by n desc limit 3""",
                (row["id"], row["flag_cycle"]))
            tricks = ", ".join(SCAM_LABELS[r["scam_type"]]
                               for r in cur.fetchall())

    if not reporters:
        send_text(
            wa_id,
            f"*{disp}*: no community reports are currently recorded in this directory.\n"
            "That does not mean the number is safe. "
            "Never share your MoMo PIN with anyone.\n"
            "Something fishy happened? Reply REPORT to log it.")
        return

    source = "user" if reporters == 1 else "users"
    threshold = (
        "This is below the directory's three-reporter flagging threshold."
        if reporters < 3 else
        "This meets the directory's three-reporter flagging threshold."
    )
    send_text(
        wa_id,
        f"*{disp}*: community reports from {reporters} distinct WhatsApp {source}.\n"
        f"{threshold}\n"
        f"Reported categories: {tricks}.\n"
        "These reports are not independently verified and are not proof of fraud. "
        "A report count does not establish whether a number is safe.\n"
        "Do not send money based only on a message or call, or share your MoMo PIN.\n"
        "Number listed unfairly? Reply DISPUTE.\n"
        "Was this helpful? Reply YES or NO.")


def finalize_report(user, canonical, scam_type, description=None):
    """Write the report; flip the number to flagged at 3 unique reporters."""
    wa_id = user["whatsapp_id"]
    disp = display_number(canonical)
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """insert into phone_numbers (number, display_number)
               values (%s, %s)
               on conflict (number) do nothing""",
            (canonical, disp))
        cur.execute("select id, flag_cycle from phone_numbers where number = %s",
                    (canonical,))
        _nrow = cur.fetchone()
        number_id = _nrow["id"]
        cycle = _nrow["flag_cycle"]

        # One report per user per number — enforced here and by the DB constraint.
        cur.execute(
            "select 1 from reports where phone_number_id = %s and reporter_id = %s "
            "and cycle = %s",
            (number_id, user["id"], cycle))
        if cur.fetchone():
            set_state(user["id"], "idle")
            send_text(wa_id,
                      f"You've already reported *{disp}* — thanks for staying vigilant. 🙏")
            return

        cur.execute(
            """insert into reports (phone_number_id, reporter_id, scam_type, description, cycle)
               values (%s, %s, %s, %s, %s)""",
            (number_id, user["id"], scam_type, description, cycle))
        cur.execute(
            """update phone_numbers
               set report_count = report_count + 1,
                   unique_reporters = unique_reporters + 1,
                   last_reported_at = now(),
                   first_reported_at = coalesce(first_reported_at, now()),
                   risk_status = case when unique_reporters + 1 >= 3
                                      then 'flagged' else risk_status end
               where id = %s
               returning unique_reporters, risk_status""",
            (number_id,))
        updated = cur.fetchone()
        # EXPIRY SLICE: qualifying new report while F is set restarts the
        # clock by one full interval (approved SC24 / bucket (a) behavior).
        cur.execute(
            """update phone_numbers
               set fresh_review_date = now() + fresh_review_interval
               where id = %s
               and fresh_review_date is not null
               and fresh_review_interval is not null""",
            (number_id,))
        cur.execute(
            "update users set reports_made = reports_made + 1 where id = %s",
            (user["id"],))

    set_state(user["id"], "idle")
    flagged = updated["risk_status"] == "flagged"
    send_text(
        wa_id,
        f"Logged ✅ *{disp}* now has {updated['unique_reporters']} reports"
        f"{' and is flagged as risky' if flagged else ''}. "
        "Thanks — you've just protected the next person. 🙏")


def handle_dispute(user, wa_id, text):
    canonical = extract_number(text)
    if not canonical:
        send_text(wa_id,
                  "I need the number too — send it like this:\n"
                  "0551234567 this number belongs to my shop")
        return
    with db() as conn, conn.cursor() as cur:
        cur.execute("select id from phone_numbers where number = %s",
                    (canonical,))
        row = cur.fetchone()
        if not row:
            send_text(wa_id,
                      "That number isn't in our directory — nothing to dispute. 👍")
        else:
            explanation = re.sub(r"(?<!\d)(?:\+?233\d{9}|0\d{9})(?!\d)",
                                 "", text).strip()[:500] or "No explanation given."
            cur.execute(
                """insert into disputes (phone_number_id, contact, explanation)
                   values (%s, %s, %s)""",
                (row["id"], wa_id, explanation))
            send_text(wa_id,
                      "Your dispute has been recorded. For questions or supporting "
                      "information, email kwekudonkorebenezer@gmail.com.")
    set_state(user["id"], "idle")


def handle_text(user, wa_id, text):
    t = text.strip()
    low = t.lower()
    state = user["state"]

    if low == "cancel":
        set_state(user["id"], "idle")
        send_text(wa_id, "Cancelled. " + MENU)
        return

    if state == "awaiting_number":
        canonical = extract_number(t)
        if not canonical:
            send_text(wa_id,
                      "Hmm, that doesn't look like a Ghana number. "
                      "Send 10 digits starting with 0, e.g. 0551234567.")
            return
        set_state(user["id"], "awaiting_scam_type",
                  {"pending_number": canonical})
        send_text(
            wa_id,
            f"Got it: *{display_number(canonical)}*. What did they try? "
            "Reply with a number:\n"
            "1. Fake MTN / agent call\n"
            "2. \"Wrong number, I sent you money\" trick\n"
            "3. Prize, lottery or promo scam\n"
            "4. Something else (describe it)")
        return

    if state == "awaiting_scam_type":
        mapping = {"1": "fake_agent", "2": "wrong_number",
                   "3": "prize_scam", "4": "other"}
        if low not in mapping:
            send_text(wa_id, "Reply with 1, 2, 3 or 4 — or CANCEL to stop.")
            return
        canonical = (user["state_data"] or {}).get("pending_number")
        if mapping[low] == "other":
            set_state(user["id"], "awaiting_description",
                      {"pending_number": canonical})
            send_text(wa_id, "Briefly describe what happened:")
            return
        finalize_report(user, canonical, mapping[low])
        return

    if state == "awaiting_description":
        canonical = (user["state_data"] or {}).get("pending_number")
        finalize_report(user, canonical, "other", description=t[:500])
        return

    if state == "awaiting_dispute":
        handle_dispute(user, wa_id, t)
        return

    # state == "idle": route by keyword, else treat any number as a check
    if low in ("hi", "hello", "menu", "start", "1", "check"):
        send_text(wa_id, MENU if low != "check" else
                  "Send me the number you want to check — 10 digits, e.g. 0551234567.")
        return
    if low in ("help", "3"):
        send_text(wa_id, HELP_TEXT)
        return
    if low in ("report", "2"):
        set_state(user["id"], "awaiting_number")
        send_text(wa_id,
                  "OK, let's log it. Send me the scammer's number — "
                  "10 digits, e.g. 0551234567.")
        return
    if low == "dispute":
        set_state(user["id"], "awaiting_dispute")
        send_text(wa_id,
                  "Sorry about that. Send the number plus a short explanation "
                  "in one message.")
        return
    canonical = extract_number(t)
    if canonical:
        handle_check(wa_id, canonical)
        return
    send_text(wa_id,
              "I only speak numbers 😅 — send a phone number to check, "
              "or reply MENU for options.")


# --- Review + expiry ---
def apply_review(phone_number_id, decision, fresh_review_date=None):
    """Apply a reviewer decision. decision: SUPPORTS | UNDERMINES | INCONCLUSIVE.

    SUPPORTS: challenge rejected, flag stays.
    UNDERMINES: challenge upheld, flag comes down (reports are never moved).
    INCONCLUSIVE: flag stays up and fresh_review_date is set to the supplied
    F, with fresh_review_interval recorded so a later qualifying report can
    restart the clock. F must be supplied — the function refuses to invent one.
    Returns the updated phone_numbers row.
    """
    if decision not in ("SUPPORTS", "UNDERMINES", "INCONCLUSIVE"):
        raise ValueError("unknown decision")
    if decision == "INCONCLUSIVE" and fresh_review_date is None:
        raise ValueError("INCONCLUSIVE requires fresh_review_date")
    with db() as conn, conn.cursor() as cur:
        cur.execute("select * from phone_numbers where id = %s",
                    (phone_number_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError("unknown phone number")
        if decision == "SUPPORTS":
            cur.execute(
                "update disputes set status = 'rejected', reviewed_at = now() "
                "where phone_number_id = %s and status = 'pending'",
                (phone_number_id,))
            cur.execute(
                "update phone_numbers set fresh_review_date = NULL, "
                "fresh_review_interval = NULL where id = %s",
                (phone_number_id,))
        elif decision == "UNDERMINES":
            cur.execute(
                "update disputes set status = 'upheld', reviewed_at = now() "
                "where phone_number_id = %s and status = 'pending'",
                (phone_number_id,))
            cur.execute(
                "update phone_numbers set risk_status = 'clean', "
                "unique_reporters = 0, report_count = 0, "
                "fresh_review_date = NULL, fresh_review_interval = NULL "
                "where id = %s",
                (phone_number_id,))
        else:  # INCONCLUSIVE
            cur.execute(
                "update disputes set status = 'inconclusive', "
                "reviewed_at = now() "
                "where phone_number_id = %s and status = 'pending'",
                (phone_number_id,))
            cur.execute(
                "update phone_numbers set fresh_review_date = %s, "
                "fresh_review_interval = %s - now() "
                "where id = %s",
                (fresh_review_date, fresh_review_date, phone_number_id))
        cur.execute("select * from phone_numbers where id = %s",
                    (phone_number_id,))
        return cur.fetchone()


def process_expiry(now=None):
    """Lapse flags whose fresh-review date has passed.

    now defaults to real time; tests pass explicit times (that is the
    virtual clock for this slice). Idempotent: a second run changes nothing.
    Numbers with a pending dispute are skipped — a live challenge beats the
    clock. Old reports stay in the database under their old cycle (audit);
    they no longer count. Returns the list of lapsed phone_number ids.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    lapsed = []
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """select id from phone_numbers
               where risk_status = 'flagged'
               and fresh_review_date is not null
               and fresh_review_date <= %s
               and not exists (
                   select 1 from disputes
                   where disputes.phone_number_id = phone_numbers.id
                   and disputes.status = 'pending')""",
            (now,))
        ids = [r["id"] for r in cur.fetchall()]
        for pid in ids:
            cur.execute(
                """update phone_numbers
                   set risk_status = 'clean',
                       unique_reporters = 0,
                       report_count = 0,
                       flag_cycle = flag_cycle + 1,
                       lapsed_at = %s,
                       fresh_review_date = NULL,
                       fresh_review_interval = NULL
                   where id = %s""",
                (now, pid))
            lapsed.append(pid)
    return lapsed


# --- Meta webhook endpoints ---
@app.get("/webhook")
def verify():
    """Meta's one-time handshake when you register the webhook URL."""
    if (request.args.get("hub.mode") == "subscribe"
            and request.args.get("hub.verify_token") == VERIFY_TOKEN):
        return request.args.get("hub.challenge"), 200
    return "forbidden", 403


@app.post("/webhook")
def incoming():
    """Acknowledge receipt, not processing or delivery. Keep HTTP 200 to avoid
    adding retries: message handling is not idempotent and may partly commit."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                metadata = value.get("metadata") if isinstance(value, dict) else None
                if (not isinstance(metadata, dict)
                        or metadata.get("phone_number_id") != PHONE_NUMBER_ID):
                    app.logger.warning("webhook_ignored reason=phone_id_mismatch_or_missing")
                    continue
                for msg in value.get("messages", []):
                    if msg.get("type") != "text":
                        # Non-text inbound contacts count as activity for an existing
                        # account, without storing media or creating a new account.
                        # Status notifications have no messages/from and never enter.
                        if msg.get("from") and msg.get("type"):
                            with db() as conn, conn.cursor() as cur:
                                cur.execute(
                                    "update users set last_seen_at = greatest(last_seen_at, clock_timestamp()) where whatsapp_id = %s",
                                    (msg["from"],))
                        continue
                    wa_id = msg["from"]
                    user = get_user(wa_id)
                    if user["blocked"]:
                        continue
                    handle_text(user, wa_id, msg["text"]["body"])
    except Exception:
        # Exception/SQL text may include personal data; do not emit it or a traceback.
        app.logger.error("webhook_processing_failed")
    return jsonify({"ok": True})


# --- Public read-only stats (powers the ScamCheck Ghana report dashboard) ---
@app.get("/stats")
def public_stats():
    try:
        return _stats_payload()
    except Exception:
        # Never expose exception/SQL/connection details to the public or logs.
        app.logger.error("stats_failed")
        return jsonify({"ok": False, "error": "stats_unavailable"}), 500


def _stats_payload():
    """Aggregate counts only; do not enumerate individual directory records.

    Keep flagged_numbers as an empty list for legacy dashboard clients.
    Exact aggregate counts are public, not anonymisation guarantees.
    """
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "select risk_status, count(*) as n from phone_numbers group by risk_status")
        by_status = {r["risk_status"]: r["n"] for r in cur.fetchall()}

        cur.execute("select count(*) as n from reports")
        total_reports = cur.fetchone()["n"]
        cur.execute(
            "select count(*) as n from reports "
            "where created_at > now() - interval '24 hours'")
        reports_24h = cur.fetchone()["n"]
        cur.execute(
            "select count(*) as n from reports "
            "where created_at > now() - interval '7 days'")
        reports_7d = cur.fetchone()["n"]

        cur.execute("select count(*) as n from users")
        total_users = cur.fetchone()["n"]
        cur.execute(
            "select count(*) as n from users "
            "where last_seen_at > now() - interval '7 days'")
        users_7d = cur.fetchone()["n"]

        cur.execute(
            "select count(*) as n from disputes where status = 'pending'")
        disputes_pending = cur.fetchone()["n"]

        cur.execute(
            "select scam_type, count(*) as n from reports group by scam_type")
        scam_types = {r["scam_type"]: r["n"] for r in cur.fetchall()}

        cur.execute(
            """select to_char(created_at, 'YYYY-MM-DD') as day, count(*) as n
               from reports
               where created_at > now() - interval '14 days'
               group by 1 order by 1""")
        activity = [{"day": r["day"], "reports": r["n"]} for r in cur.fetchall()]

    return jsonify({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "numbers": {
            "total": sum(by_status.values()),
            "flagged": by_status.get("flagged", 0),
            "watch": by_status.get("watch", 0),
            "clean": by_status.get("clean", 0),
        },
        "reports": {
            "total": total_reports,
            "last_24h": reports_24h,
            "last_7d": reports_7d,
        },
        "users": {"total": total_users, "active_7d": users_7d},
        "disputes_pending": disputes_pending,
        "scam_types": scam_types,
        "flagged_numbers": [],
        "recent_activity": activity,
    })


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)))
