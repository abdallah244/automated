const crypto = require("crypto");
require("dotenv").config();
const express = require("express");

const app = express();

const MAX_MESSAGES = Number(process.env.MAX_MESSAGES || 200);
const messageStore = [];

function addMessage(entry) {
  messageStore.push(entry);
  if (messageStore.length > MAX_MESSAGES) {
    messageStore.splice(0, messageStore.length - MAX_MESSAGES);
  }
}

function isDashboardAuthorized(req) {
  const expected = process.env.DASHBOARD_TOKEN;
  if (!expected) return true;

  const got = req.header("x-dashboard-token") || req.query.token;
  return Boolean(got) && got === expected;
}

function requireDashboardAuth(req, res, next) {
  if (!isDashboardAuthorized(req)) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  return next();
}

// Raw body needed for signature verification
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
);

function timingSafeEqual(a, b) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function verifyMetaSignature(req) {
  const appSecret = process.env.WHATSAPP_APP_SECRET;
  if (!appSecret) return true; // allow if not configured

  const signature = req.header("x-hub-signature-256");
  if (!signature || !signature.startsWith("sha256=")) return false;

  const expected =
    "sha256=" +
    crypto
      .createHmac("sha256", appSecret)
      .update(req.rawBody || "")
      .digest("hex");

  return timingSafeEqual(signature, expected);
}

app.get("/api/health", (req, res) => {
  res.status(200).json({ ok: true, service: "whatsapp-webhook-vercel" });
});

app.get("/api/messages", requireDashboardAuth, (req, res) => {
  const newestFirst = [...messageStore].reverse();
  res.status(200).json({ ok: true, count: newestFirst.length, messages: newestFirst });
});

app.post("/api/clear", requireDashboardAuth, (req, res) => {
  messageStore.length = 0;
  res.status(200).json({ ok: true });
});

app.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(`<!doctype html>
<html lang="ar" dir="rtl">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>WhatsApp Webhook Dashboard</title>
    <style>
      :root { color-scheme: light; }
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 24px; background: #fafafa; }
      .wrap { max-width: 980px; margin: 0 auto; }
      .row { display: grid; grid-template-columns: 1fr; gap: 16px; }
      @media (min-width: 900px) { .row { grid-template-columns: 1fr 1fr; } }
      h1 { margin: 0 0 6px; font-size: 20px; }
      .sub { margin: 0 0 18px; color: #555; font-size: 13px; }
      .card { background: white; border: 1px solid #e6e6e6; border-radius: 12px; padding: 14px; }
      label { display: block; font-size: 12px; color: #333; margin-bottom: 6px; }
      input, textarea { width: 100%; box-sizing: border-box; padding: 10px; border: 1px solid #ddd; border-radius: 10px; font-size: 14px; }
      textarea { min-height: 90px; resize: vertical; }
      .btns { display: flex; gap: 10px; flex-wrap: wrap; }
      button { border: 1px solid #ddd; background: #111; color: #fff; padding: 10px 12px; border-radius: 10px; cursor: pointer; font-size: 14px; }
      button.secondary { background: #fff; color: #111; }
      button:disabled { opacity: .6; cursor: not-allowed; }
      .hint { font-size: 12px; color: #666; margin-top: 8px; }
      .log { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; background: #0b1020; color: #e7e7e7; padding: 12px; border-radius: 12px; max-height: 420px; overflow: auto; }
      .msg { border: 1px solid #eee; border-radius: 12px; padding: 10px; margin-bottom: 10px; background: #fff; }
      .meta { font-size: 12px; color: #666; display: flex; gap: 10px; flex-wrap: wrap; }
      .pill { background: #f1f1f1; padding: 2px 8px; border-radius: 999px; }
      .in { border-right: 4px solid #4caf50; }
      .out { border-right: 4px solid #2196f3; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <h1>لوحة WhatsApp Webhook</h1>
      <p class="sub">عرض آخر الرسائل القادمة + إرسال رسالة لأي رقم (عبر Cloud API).</p>

      <div class="row">
        <div class="card">
          <h2 style="margin:0 0 10px; font-size:16px;">الإعدادات</h2>
          <label>Dashboard Token (اختياري)</label>
          <input id="token" placeholder="لو عندك DASHBOARD_TOKEN اكتبه هنا" />
          <div class="hint">لو عايز تقفل اللوحة: عيّن متغير البيئة <b>DASHBOARD_TOKEN</b> على Vercel، وبعدها اكتب نفس القيمة هنا.</div>
          <hr style="border:none; border-top:1px solid #eee; margin:14px 0;" />

          <h2 style="margin:0 0 10px; font-size:16px;">إرسال رسالة</h2>
          <label>رقم واتساب (بصيغة دولية بدون +)</label>
          <input id="to" placeholder="مثال: 2010xxxxxxx" />
          <label style="margin-top:10px;">نص الرسالة</label>
          <textarea id="text" placeholder="اكتب الرسالة..."></textarea>
          <div class="btns" style="margin-top:10px;">
            <button id="sendBtn">إرسال</button>
            <button class="secondary" id="clearBtn" type="button">مسح السجل</button>
          </div>
          <div class="hint" id="sendStatus"></div>
        </div>

        <div class="card">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
            <h2 style="margin:0; font-size:16px;">الرسائل الواردة</h2>
            <div class="btns">
              <button class="secondary" id="refreshBtn" type="button">تحديث</button>
              <button class="secondary" id="toggleBtn" type="button">إيقاف التحديث التلقائي</button>
            </div>
          </div>
          <div class="hint">التحديث التلقائي كل 2 ثانية. ملاحظة: على Vercel التخزين في الذاكرة قد يختفي بعد إعادة تشغيل الدالة.</div>
          <div id="list" style="margin-top:12px;"></div>
          <details style="margin-top:12px;">
            <summary>Debug JSON</summary>
            <div class="log" id="raw"></div>
          </details>
        </div>
      </div>
    </div>

    <script>
      const $ = (id) => document.getElementById(id);
      const tokenKey = 'dashboard_token';
      const state = { timer: null, auto: true, last: null };

      $('token').value = localStorage.getItem(tokenKey) || '';
      $('token').addEventListener('input', () => {
        localStorage.setItem(tokenKey, $('token').value || '');
      });

      function headers() {
        const t = ($('token').value || '').trim();
        return t ? { 'x-dashboard-token': t } : {};
      }

      function escapeHtml(s) {
        return String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      }

      async function refresh() {
        try {
          const resp = await fetch('/api/messages', { headers: headers() });
          const json = await resp.json();
          state.last = json;
          $('raw').textContent = JSON.stringify(json, null, 2);

          if (!resp.ok) {
            $('list').innerHTML =
              '<div class="hint">' +
              escapeHtml((json && json.error) || 'Unauthorized') +
              '</div>';
            return;
          }

          const items = json.messages || [];
          if (items.length === 0) {
            $('list').innerHTML = '<div class="hint">لا توجد رسائل بعد.</div>';
            return;
          }

          $('list').innerHTML = items.map((m) => {
            const cls = m.direction === 'out' ? 'msg out' : 'msg in';
            const who = m.direction === 'out' ? 'to: ' + (m.to || '') : 'from: ' + (m.from || '');
            return (
              '\n' +
              '  <div class="' + cls + '">' +
              '    <div class="meta">' +
              '      <span class="pill">' + escapeHtml(m.direction || '') + '</span>' +
              '      <span class="pill">' + escapeHtml(who) + '</span>' +
              '      <span class="pill">' + escapeHtml(m.time || '') + '</span>' +
              '      <span class="pill">' + escapeHtml(m.type || '') + '</span>' +
              '    </div>' +
              '    <div style="margin-top:8px; font-size:14px;">' + escapeHtml(m.text || '') + '</div>' +
              '  </div>' +
              '\n'
            );
          }).join('');
        } catch (e) {
          $('list').innerHTML =
            '<div class="hint">فشل التحديث: ' +
            escapeHtml((e && e.message) || e) +
            '</div>';
        }
      }

      async function send() {
        $('sendBtn').disabled = true;
        $('sendStatus').textContent = 'جارٍ الإرسال...';
        try {
          const to = ($('to').value || '').trim();
          const text = ($('text').value || '').trim();
          const resp = await fetch('/api/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...headers() },
            body: JSON.stringify({ to, text }),
          });
          const json = await resp.json().catch(() => ({}));
          if (!resp.ok) {
            $('sendStatus').textContent = 'خطأ: ' + (json?.error ? JSON.stringify(json.error) : resp.status);
          } else {
            $('sendStatus').textContent = 'تم الإرسال.';
            $('text').value = '';
            await refresh();
          }
        } catch (e) {
          $('sendStatus').textContent = 'فشل الإرسال: ' + (e?.message || e);
        } finally {
          $('sendBtn').disabled = false;
        }
      }

      async function clearLog() {
        if (!confirm('مسح السجل؟')) return;
        const resp = await fetch('/api/clear', { method: 'POST', headers: headers() });
        await resp.json().catch(() => ({}));
        await refresh();
      }

      function startAuto() {
        stopAuto();
        state.timer = setInterval(refresh, 2000);
        state.auto = true;
        $('toggleBtn').textContent = 'إيقاف التحديث التلقائي';
      }
      function stopAuto() {
        if (state.timer) clearInterval(state.timer);
        state.timer = null;
        state.auto = false;
        $('toggleBtn').textContent = 'تشغيل التحديث التلقائي';
      }

      $('refreshBtn').addEventListener('click', refresh);
      $('toggleBtn').addEventListener('click', () => state.auto ? stopAuto() : startAuto());
      $('sendBtn').addEventListener('click', send);
      $('clearBtn').addEventListener('click', clearLog);

      refresh();
      startAuto();
    </script>
  </body>
</html>`);
});

// Meta webhook verification
app.get("/api/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === process.env.WHATSAPP_VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }

  return res.sendStatus(403);
});

// Receive WhatsApp events
app.post("/api/webhook", async (req, res) => {
  if (!verifyMetaSignature(req)) {
    return res.sendStatus(401);
  }

  // WhatsApp Cloud API sends { object: 'whatsapp_business_account', entry: [...] }
  // We just log a compact view.
  try {
    const body = req.body;

    const changes = body?.entry?.flatMap((e) => e.changes || []) || [];
    const value = changes.map((c) => c.value).filter(Boolean);

    // Extract incoming messages (if any)
    const messages = value.flatMap((v) => v.messages || []);

    if (messages.length > 0) {
      const simplified = messages.map((m) => {
        const time = m.timestamp
          ? new Date(Number(m.timestamp) * 1000).toISOString()
          : new Date().toISOString();
        return {
          direction: "in",
          from: m.from,
          id: m.id,
          time,
          type: m.type,
          text: m.text?.body,
        };
      });
      simplified.forEach(addMessage);
      console.log("Incoming messages:", JSON.stringify(simplified));
    } else {
      console.log("Webhook event:", JSON.stringify(body));
    }

    // IMPORTANT: respond quickly
    return res.sendStatus(200);
  } catch (err) {
    console.error("Webhook error:", err);
    return res.sendStatus(200);
  }
});

// Simple send helper: POST /api/send { to: "<phone>", text: "hi" }
app.post("/api/send", async (req, res) => {
  if (!isDashboardAuthorized(req)) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }

  const token = process.env.WHATSAPP_TOKEN;
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;

  if (!token || !phoneNumberId) {
    return res.status(400).json({
      ok: false,
      error: "Missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID",
    });
  }

  const { to, text } = req.body || {};
  if (!to || !text) {
    return res.status(400).json({ ok: false, error: "Provide { to, text }" });
  }

  try {
    const url = `https://graph.facebook.com/v20.0/${phoneNumberId}/messages`;
    const payload = {
      messaging_product: "whatsapp",
      to,
      type: "text",
      text: { body: text },
    };

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      return res.status(resp.status).json({ ok: false, error: data });
    }

    addMessage({
      direction: "out",
      to,
      time: new Date().toISOString(),
      type: "text",
      text,
      result: data,
    });

    return res.status(200).json({ ok: true, data });
  } catch (err) {
    console.error("Send error:", err);
    return res.status(500).json({ ok: false, error: "Failed to send message" });
  }
});

// Vercel serverless export
module.exports = (req, res) => app(req, res);

// Local dev runner
if (!process.env.VERCEL) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`);
  });
}
