# ScamCheck Ghana

**Check a number before you send money.** ScamCheck Ghana is a WhatsApp-first scam-number directory: send the bot any suspicious Ghanaian phone number and get an instant verdict, or report a scammer in one tap. No app, no sign-up.

Built by Royal Keita (Ebenezer Kweku Donkor), Cape Coast. Hack For Equity, Mobile Money Fraud Hackathon: Track 01 (Spot it early) and Track 04 (Lean on the community).

## How it works

| User sends | Bot does |
|---|---|
| `hi` / `menu` | Shows the menu: CHECK, REPORT, HELP |
| a phone number (e.g. `0551234567`) | Looks it up and replies ✅ no reports, or 🚨 reported N times with the common tricks |
| `REPORT` | Asks for the number, then the scam type (fake MTN agent, "wrong number, I sent you money", prize scam, or something else) |
| `DISPUTE` | Lets the owner of a wrongly flagged number ask for human review |
| `CANCEL` | Ends the current flow |

**Trust rules**
- A number is **flagged after 3 different people** report it.
- One report per WhatsApp user per number (enforced in code and by a database constraint), so nobody can spam a rival's line.
- Disputes go to a human for review.
- The public `/stats` endpoint lists only flagged numbers plus aggregate counts. No reporter identities, contacts or WhatsApp IDs are ever exposed.
- Reports come from the community and are **not verified by MTN or the police**; the bot says so.

Accepts `0XXXXXXXXX`, `+233XXXXXXXXX` and `233XXXXXXXXX`, validated against Ghana mobile prefixes.

## Stack

Built to run almost free, so the service can stay free for users:

- **Meta WhatsApp Cloud API** for messaging
- **Python / Flask** webhook (`webhook.py`), served by gunicorn
- **Supabase Postgres** database (`schema.sql`)
- **Render** hosting

## Setup

### 1. Database (Supabase)
1. Create a Supabase project.
2. Open **SQL Editor**, paste in `schema.sql`, and run it.
3. Copy the connection string from **Project Settings → Database** (use the pooler URI on Render). This is `DATABASE_URL`.

### 2. WhatsApp (Meta for Developers)
1. Create an app with the **WhatsApp** product.
2. Note the **Phone number ID** → `PHONE_NUMBER_ID`.
3. Create a **System User** in Meta Business Settings, give it the app and WhatsApp account, and generate a **permanent access token** with `whatsapp_business_messaging` and `whatsapp_business_management`. → `WHATSAPP_TOKEN`. (The temporary token from the dashboard expires in 24 hours.)
4. Make up any secret string → `VERIFY_TOKEN`.

### 3. Environment variables

| Variable | What it is |
|---|---|
| `VERIFY_TOKEN` | Your own secret string for Meta's webhook handshake |
| `WHATSAPP_TOKEN` | Permanent System User access token |
| `META_APP_SECRET` | Meta app secret used to verify incoming webhook signatures |
| `PHONE_NUMBER_ID` | The bot's WhatsApp phone number ID |
| `DATABASE_URL` | Supabase Postgres connection string |
| `GRAPH_VERSION` | Optional, defaults to `v21.0` |
| `PORT` | Optional for local runs, defaults to `5000` |

Never commit these values. Set them in Render's **Environment** tab.

### 4. Run locally
```bash
pip install -r requirements.txt
export VERIFY_TOKEN=... WHATSAPP_TOKEN=... PHONE_NUMBER_ID=... DATABASE_URL=...
python webhook.py
```
Expose it with a tunnel (e.g. ngrok) to test with Meta.

### 5. Deploy on Render
1. New **Web Service** from this repo.
2. Build command: `pip install -r requirements.txt`
3. Start command: `gunicorn webhook:app`
4. Add the environment variables.
5. In Meta's WhatsApp **Configuration**, set the callback URL to `https://<your-app>.onrender.com/webhook`, enter your `VERIFY_TOKEN`, and subscribe to the **messages** field.

Note: Render's free tier sleeps when idle, so the first message after a quiet spell can be slow.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/webhook` | Meta verification handshake |
| POST | `/webhook` | Signed incoming WhatsApp messages; unsigned/invalid signatures are rejected |
| GET | `/stats` | Public, privacy-safe JSON for the dashboard: totals, reports in the last 24h and 7 days, scam types, up to 50 flagged numbers, 14-day activity |

## Roadmap
- Replies in Twi and other local languages
- Spotting repeat scam scripts, not just numbers
- An API for merchants and MoMo agents to check numbers
- Partnerships with telcos and banks for reach

## Safety reminder
A clean result doesn't mean a number is safe. Scammers use new numbers daily. **Never share your MoMo PIN with anyone.**
