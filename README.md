# WhatsApp Webhook (Node + Express) on Vercel

## Endpoints

- `GET /api/webhook` verification for Meta webhook
- `POST /api/webhook` receive WhatsApp events
- `POST /api/send` send a WhatsApp message (simple helper)
- `GET /` simple dashboard UI
- `GET /api/messages` list recent messages (dashboard)
- `POST /api/clear` clear in-memory messages (dashboard)
- `GET /api/health` health check JSON

## Environment variables

Set these in Vercel Project Settings → Environment Variables:

- `WHATSAPP_VERIFY_TOKEN` (same value you put in Meta webhook setup)
- `WHATSAPP_TOKEN` (permanent/system user access token)
- `WHATSAPP_PHONE_NUMBER_ID` (from WhatsApp Cloud API)
- `WHATSAPP_APP_SECRET` (optional but recommended for validating `X-Hub-Signature-256`)
- `DASHBOARD_TOKEN` (optional: protect dashboard + send/messages endpoints)
- `MAX_MESSAGES` (optional: default 200)

## Local run

```bash
npm install
npm run dev
```

Server runs on `http://localhost:3000`.

## Meta Webhook setup

In your Meta App → WhatsApp → Configuration:

- Callback URL: `https://YOUR-VERCEL-DOMAIN.vercel.app/api/webhook`
- Verify token: same as `WHATSAPP_VERIFY_TOKEN`
- Subscribe to: `messages`

## Notes

- Vercel will invoke `api/index.js` as a serverless function.
- Signature verification is enabled only if `WHATSAPP_APP_SECRET` is set.
- The message list is stored in memory (may reset on Vercel cold starts/redeploys).
