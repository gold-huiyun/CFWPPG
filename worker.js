
export default {
  async fetch(request, env, ctx) {
    // ===== 配置项 =====
    const TARGET_HOST   = env.TARGET_HOST   || "www.example.com"; // 反向代理目标网站
    const MAX_FAILS     = parseInt(env.MAX_FAILS     || "3",     10); // 连续最大错误次数
    const FAIL_TTL      = parseInt(env.FAIL_TTL      || "900",   10); // 错误计数 TTL（秒）
    const BAN_TTL       = parseInt(env.BAN_TTL       || "3600",  10); // 封禁 TTL（秒）
    const SESSION_TTL   = parseInt(env.SESSION_TTL   || "86400", 10); // 会话有效期（秒）
    const REALM         = env.REALM || "Protected Gateway";
    // 若你的 Worker 只绑定在 example.com/proxy/*，请设 BASE_PATH="/proxy"
    const BASE_PATH     = (env.BASE_PATH || "").replace(/\/$/, "");
    const ROOT_PATH     = BASE_PATH || "/";
    const LOGIN_PAGE    = `${BASE_PATH}/login`;
    const LOGIN_API     = `${BASE_PATH}/__auth`;

    // 变量Secrets & KV
    const AUTH_PASSWORD = env.AUTH_PASSWORD; // 认证密码，在worker设置中变量添加
    const COOKIE_SECRET = env.COOKIE_SECRET; // 13位随机字符，在worker设置中变量添加
    const KV            = env.AUTH_STORE;    // ※先在存储和数据库创建 Workers KV，名称随意，然后在work绑定-添加绑定-KV 命名空间-变量名称AUTH_STORE，并选择你创建的KV
    if (!AUTH_PASSWORD || !COOKIE_SECRET || !KV) {
      return new Response("Server not configured. Missing AUTH_PASSWORD / COOKIE_SECRET / AUTH_STORE.", { status: 500 });
    }

    // ===== 工具函数 =====
    const enc = new TextEncoder();
    function parseCookies(cookieHeader) {
      const cookies = {};
      if (!cookieHeader) return cookies;
      cookieHeader.split(";").forEach(c => {
        const [k, ...rest] = c.split("=");
        if (!k) return;
        cookies[k.trim()] = rest.join("=").trim();
      });
      return cookies;
    }
    function b64url(buf) {
      const bytes = new Uint8Array(buf);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    async function hmacSign(data, secret) {
      const key = await crypto.subtle.importKey(
        "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
      return b64url(sig);
    }
    async function hmacVerify(data, signature, secret) {
      const key = await crypto.subtle.importKey(
        "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
      );
      const expected = await crypto.subtle.sign("HMAC", key, enc.encode(data));
      const expectedB64 = b64url(expected);
      return constantTimeEqual(signature, expectedB64);
    }
    function constantTimeEqual(a, b) {
      if (a.length !== b.length) return false;
      let r = 0;
      for (let i = 0; i < a.length; i++) r ^= a.charCodeAt(i) ^ b.charCodeAt(i);
      return r === 0;
    }
    function setSecurityHeaders(headers) {
      headers.set("X-Content-Type-Options", "nosniff");
      headers.set("X-Frame-Options", "DENY");
      headers.set("Referrer-Policy", "no-referrer");
      headers.set("Permissions-Policy", "geolocation=()");
      headers.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
      headers.set("Pragma", "no-cache");
    }

    function renderLoginPage(message = "") {
      const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>${REALM} - 登录</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, 'PingFang SC', 'Microsoft YaHei', sans-serif; background:#0f172a; color:#e5e7eb; display:flex; min-height:100vh; align-items:center; justify-content:center; }
  .box { width: 360px; background:#111827; padding:24px; border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.4); }
  h1 { font-size:18px; margin:0 0 16px; }
  label { display:block; margin:8px 0 6px; }
  input[type="password"] { width:100%; padding:10px 12px; border-radius:8px; border:1px solid #374151; background:#111827; color:#e5e7eb; }
  button { width:100%; margin-top:14px; padding:10px 12px; border-radius:8px; background:#2563eb; color:#fff; border:none; cursor:pointer; }
  button[disabled] { opacity:.75; cursor:not-allowed; }
  .msg { margin-top:12px; color:#fca5a5; min-height:20px; }
  .footer { margin-top:16px; font-size:12px; color:#9ca3af; text-align:center; }
</style>
</head>
<body>
  <div class="box">
    <h1>${REALM} - 访问控制</h1>
    <label for="pwd">访问密码</label>
    <input id="pwd" name="password" type="password" autocomplete="new-password" required />
    <button id="go">进入</button>
    <div class="msg" id="msg" role="status" aria-live="polite">${message || ""}</div>
    <div class="footer">连续输错3次将封禁IP</div>
  </div>
<script>
  const API = ${JSON.stringify(LOGIN_API)};
  const ROOT = ${JSON.stringify(ROOT_PATH)};
  const btn = document.getElementById('go');
  const pwd = document.getElementById('pwd');
  const msg = document.getElementById('msg');

  async function doLogin() {
    msg.textContent = "";
    msg.style.color = "#fca5a5"; // 默认红色（错误）
    const val = (pwd.value || "").trim();
    if (!val) { msg.textContent = "请输入密码"; return; }

    try {
      const body = new URLSearchParams({ password: val });
      const resp = await fetch(API, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
        redirect: "manual",
        credentials: "same-origin"
      });

      // 成功：显示提示后跳转
      if (resp.status === 200) {
        const data = await resp.json().catch(() => ({}));
        if (data && data.ok) {
          msg.textContent = "密码正确，正在反代网站……";
          msg.style.color = "#34d399";          // 绿色
          btn.disabled = true;
          btn.textContent = "请稍候…";
          await new Promise(r => setTimeout(r, 600)); // 给浏览器写入 HttpOnly Cookie 一点时间
          location.href = ROOT;
          return;
        }
      }

      if (resp.status === 403) {
        const text = await resp.text();
        msg.textContent = text || "拒绝访问";
        msg.style.color = "#fca5a5";
        return;
      }

      const text = await resp.text();
      msg.textContent = text || ("登录失败，状态码：" + resp.status);
      msg.style.color = "#fca5a5";
    } catch (e) {
      msg.textContent = "网络错误：" + e;
      msg.style.color = "#fca5a5";
    }
  }

  btn.addEventListener('click', doLogin);
  pwd.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') doLogin(); });
</script>
</body>
</html>`;
      const resp = new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
      setSecurityHeaders(resp.headers);
      return resp;
    }

    // ===== 业务逻辑 =====
    const url = new URL(request.url);
    const isHttps = url.protocol === "https:";
    const ipBanKey = `ban:${request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown"}`;
    const failKey  = ipBanKey.replace(/^ban:/, "fail:");

    // 封禁检查
    if (await KV.get(ipBanKey)) {
      return new Response("访问已被封禁，请稍后再试。", {
        status: 403,
        headers: { "Content-Type": "text/plain; charset=utf-8", "Retry-After": `${BAN_TTL}` }
      });
    }

    // 登录页（未认证显示；已认证访问登录页则跳根）
    if (url.pathname === LOGIN_PAGE) {
      const cookies = parseCookies(request.headers.get("Cookie"));
      const session = cookies["AUTH_SESSION"];
      let authed = false;
      if (session) {
        const parts = session.split(".");
        // v1.exp.signature（不再绑定IP）
        if (parts.length === 3 && parts[0] === "v1") {
          const exp = parseInt(parts[1], 10);
          const sig = parts[2];
          if (!Number.isNaN(exp) && exp > Math.floor(Date.now() / 1000)) {
            const payload = `v1.${exp}`;
            authed = await hmacVerify(payload, sig, COOKIE_SECRET);
          }
        }
      }
      if (authed) {
        return new Response(null, { status: 302, headers: { Location: ROOT_PATH } });
      }
      return renderLoginPage();
    }

    // 登录 API：POST /__auth
    if (url.pathname === LOGIN_API) {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }

      const contentType = request.headers.get("Content-Type") || "";
      let password = "";
      if (contentType.includes("application/x-www-form-urlencoded")) {
        const form = await request.formData();
        password = (form.get("password") || "").toString();
      } else if (contentType.includes("application/json")) {
        const json = await request.json().catch(() => ({ }));
        password = (json.password || "").toString();
      } else {
        const text = await request.text();
        const m = text.match(/password=([^&]+)/);
        password = m ? decodeURIComponent(m[1]) : text;
      }

      if (password === AUTH_PASSWORD) {
        const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
        const payload = `v1.${exp}`;                 // 不绑定 IP，避免误判
        const sig = await hmacSign(payload, COOKIE_SECRET);
        const cookieValue = `${payload}.${sig}`;

        await KV.delete(failKey);

        const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
        // 按协议智能设置 Secure：HTTPS 时加；HTTP 调试时不加
        const secureAttr = isHttps ? " Secure;" : "";
        headers.append(
          "Set-Cookie",
          `AUTH_SESSION=${cookieValue}; Path=${ROOT_PATH}; Max-Age=${SESSION_TTL}; HttpOnly;${secureAttr} SameSite=Lax`
        );

        const resp = new Response(JSON.stringify({ ok: true }), { status: 200, headers });
        setSecurityHeaders(resp.headers);
        return resp;
      } else {
        const current = parseInt((await KV.get(failKey)) || "0", 10) + 1;
        if (current >= MAX_FAILS) {
          await KV.put(ipBanKey, "1", { expirationTtl: BAN_TTL });
          await KV.delete(failKey);
          return new Response("拒绝访问：连续错误过多，已封禁该IP。", { status: 403, headers: { "Content-Type": "text/plain; charset=utf-8" } });
        } else {
          await KV.put(failKey, String(current), { expirationTtl: FAIL_TTL });
          const msg = `密码错误（已错误 ${current}/${MAX_FAILS} 次）`;
          return new Response(msg, { status: 403, headers: { "Content-Type": "text/plain; charset=utf-8" } });
        }
      }
    }

    // 会话验证（其它所有路径）
    const cookies = parseCookies(request.headers.get("Cookie"));
    let authed = false;
    const session = cookies["AUTH_SESSION"];
    if (session) {
      const parts = session.split(".");
      if (parts.length === 3 && parts[0] === "v1") {
        const exp = parseInt(parts[1], 10);
        const sig = parts[2];
        if (!Number.isNaN(exp) && exp > Math.floor(Date.now() / 1000)) {
          const payload = `v1.${exp}`;
          authed = await hmacVerify(payload, sig, COOKIE_SECRET);
        }
      }
    }

    // 未认证：无论访问什么路径，都给登录页（避免“没反应”）
    if (!authed) {
      return renderLoginPage();
    }

    // ===== 通过认证：按你的示例进行反代（改 hostname + 直接 fetch） =====
    // 等同于：
    // addEventListener("fetch", e => {
    //   let url = new URL(e.request.url);
    //   url.hostname = "alistv3.huiyun.cf";
    //   let req = new Request(url, e.request);
    //   e.respondWith(fetch(req));
    // })
    const upstreamURL = new URL(request.url);
    upstreamURL.hostname = TARGET_HOST;

    const proxyRequest = new Request(upstreamURL.toString(), request);

    let originResp;
    try {
      originResp = await fetch(proxyRequest);
    } catch (e) {
      return new Response(`上游站点不可达：${e}`, { status: 502, headers: { "Content-Type": "text/plain; charset=utf-8" } });
    }

    // （可选）重写重定向 Location，使浏览器仍留在本域/前缀
    const respHeaders = new Headers(originResp.headers);
    const loc = respHeaders.get("Location");
    if (loc) {
      try {
        const locUrl = new URL(loc, `https://${TARGET_HOST}`);
        if (locUrl.host === TARGET_HOST) {
          const rewritten = `${BASE_PATH}${locUrl.pathname}${locUrl.search}`;
          respHeaders.set("Location", rewritten || ROOT_PATH);
        }
      } catch { /* ignore */ }
    }

    // 出于安全，避免把上游的 Set-Cookie 直接透传到你域名
    respHeaders.delete("Set-Cookie");

    const proxied = new Response(originResp.body, { status: originResp.status, headers: respHeaders });
    setSecurityHeaders(proxied.headers);
    return proxied;
  }
};
