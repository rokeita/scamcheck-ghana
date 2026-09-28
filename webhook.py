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
    """Fetch the user row, creating it (and touching last_seen) on first contact."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("select * from users where whatsapp_id = %s", (wa_id,))
        user = cur.fetchone()
        if user:
            cur.execute(
                "update users set last_seen_at = now() where id = %s",
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
    requests.post(
        API_URL,
        headers={"Authorization": f"Bearer {WHATSAPP_TOKEN}"},
        json={"messaging_product": "whatsapp",
              "to": to,
              "type": "text",
              "text": {"body": body}},
        timeout=15,
    )


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

    if not row or row["risk_status"] == "clean":
        send_text(
            wa_id,
            f"✅ *{disp}* has no fraud reports.\n"
            "That doesn't guarantee safety — scammers use new numbers daily. "
            "Never share your MoMo PIN with anyone.\n"
            "Something fishy happened? Reply REPORT to log it.")
        return

    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """select scam_type, count(*) as n from reports
               where phone_number_id = %s
               group by scam_type order by n desc limit 3""",
            (row["id"],))
        tricks = ", ".join(SCAM_LABELS[r["scam_type"]] for r in cur.fetchall())

    send_text(
        wa_id,
        f"🚨 *{disp}* has been reported {row['unique_reporters']} times.\n"
        f"Common tricks: {tricks}.\n"
        "⚠️ Do NOT send money or share your PIN.\n"
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
        cur.execute("select id from phone_numbers where number = %s",
                    (canonical,))
        number_id = cur.fetchone()["id"]

        # One report per user per number — enforced here and by the DB constraint.
        cur.execute(
            "select 1 from reports where phone_number_id = %s and reporter_id = %s",
            (number_id, user["id"]))
        if cur.fetchone():
            set_state(user["id"], "idle")
            send_text(wa_id,
                      f"You've already reported *{disp}* — thanks for staying vigilant. 🙏")
            return

        cur.execute(
            """insert into reports (phone_number_id, reporter_id, scam_type, description)
               values (%s, %s, %s, %s)""",
            (number_id, user["id"], scam_type, description))
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
                      "Received. A human reviews every dispute within 48 hours. 🙏")
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
    """Receive user messages. Always 200 — Meta retries anything else,
    and the reports table's unique constraint makes retries harmless."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                for msg in change.get("value", {}).get("messages", []):
                    if msg.get("type") != "text":
                        continue
                    wa_id = msg["from"]
                    user = get_user(wa_id)
                    if user["blocked"]:
                        continue
                    handle_text(user, wa_id, msg["text"]["body"])
    except Exception:
        app.logger.exception("webhook error")
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)))
