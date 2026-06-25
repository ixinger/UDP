import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import net from "node:net";
import fs from "node:fs";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { URL, URLSearchParams } from "node:url";

loadDotEnv();

const CONFIG = {
  host: process.env.HOST || "127.0.0.1",
  port: Number(process.env.PORT || 8787),
  password: process.env.PROXY_PASSWORD || "",
  secret: process.env.SESSION_SECRET || "",
  allowPrivateIps: parseBoolean(process.env.ALLOW_PRIVATE_IPS, false),
  allowedHosts: parseList(process.env.ALLOWED_HOSTS),
  blockedHosts: new Set([
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    ...parseList(process.env.EXTRA_BLOCKED_HOSTS),
  ]),
  maxRedirects: Number(process.env.MAX_REDIRECTS || 8),
  maxTargetLength: Number(process.env.MAX_TARGET_LENGTH || 4096),
};

if (!CONFIG.secret) {
  CONFIG.secret = randomBytes(32).toString("hex");
  console.warn("SESSION_SECRET is not set. Login sessions will reset when the process restarts.");
}

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const BLOCKED_REQUEST_HEADERS = new Set([
  "authorization",
  "cookie",
  "host",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-proxy-password",
  "x-real-ip",
]);

export const server = http.createServer(async (req, res) => {
  try {
    await route(req, res);
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: "Internal server error" });
  }
});

server.on("clientError", (_error, socket) => {
  socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

if (isMainModule()) {
  if (!CONFIG.password) {
    console.error("Missing PROXY_PASSWORD. Set it in .env or environment variables.");
    process.exit(1);
  }

  server.listen(CONFIG.port, CONFIG.host, () => {
    console.log(`Universal Download Proxy listening on http://${CONFIG.host}:${CONFIG.port}`);
  });
}

async function route(req, res) {
  const requestUrl = getRequestUrl(req);

  if (req.method === "OPTIONS") {
    sendCors(res, 204);
    return;
  }

  if (req.method === "GET" && requestUrl.pathname === "/") {
    sendHtml(res, 200, renderHome(req));
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/login") {
    await handleLogin(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/logout") {
    clearSession(res);
    redirect(res, "/");
    return;
  }

  if (requestUrl.pathname === "/healthz") {
    sendJson(res, 200, { ok: true });
    return;
  }

  if (!["GET", "HEAD"].includes(req.method || "")) {
    sendJson(res, 405, { error: "Method not allowed" });
    return;
  }

  if (requestUrl.pathname !== "/proxy" && !requestUrl.pathname.startsWith("/http")) {
    sendJson(res, 404, { error: "Not found" });
    return;
  }

  if (!isAuthorized(req, requestUrl)) {
    sendJson(res, 401, { error: "Unauthorized" }, { "www-authenticate": 'Bearer realm="Universal Download Proxy"' });
    return;
  }

  const targetResult = resolveTargetUrl(requestUrl);
  if (!targetResult.ok) {
    sendJson(res, 400, { error: targetResult.message });
    return;
  }

  const validation = await validateTarget(targetResult.url);
  if (!validation.ok) {
    sendJson(res, 403, { error: validation.message });
    return;
  }

  await proxyWithRedirects(req, res, targetResult.url);
}

async function handleLogin(req, res) {
  const body = await readBody(req, 16 * 1024);
  const params = new URLSearchParams(body);
  const password = params.get("password") || "";
  const next = sanitizeNext(params.get("next") || "/");

  if (!timingSafeStringEqual(password, CONFIG.password)) {
    sendHtml(res, 401, renderHome(req, "密码错误，请重试。"));
    return;
  }

  setSession(res);
  redirect(res, next);
}

async function proxyWithRedirects(clientReq, clientRes, startUrl) {
  let targetUrl = startUrl;

  for (let redirectCount = 0; redirectCount <= CONFIG.maxRedirects; redirectCount += 1) {
    const validation = await validateTarget(targetUrl);
    if (!validation.ok) {
      sendJson(clientRes, 403, { error: validation.message });
      return;
    }

    const upstreamResponse = await requestUpstream(clientReq, targetUrl, validation.resolvedAddress);

    if (!isRedirect(upstreamResponse.statusCode)) {
      pipeUpstreamResponse(clientReq, clientRes, upstreamResponse, targetUrl);
      return;
    }

    const location = upstreamResponse.headers.location;
    upstreamResponse.resume();

    if (!location) {
      pipeUpstreamResponse(clientReq, clientRes, upstreamResponse, targetUrl);
      return;
    }

    targetUrl = new URL(location, targetUrl);
    targetUrl.username = "";
    targetUrl.password = "";
  }

  sendJson(clientRes, 502, { error: `Too many redirects. Limit is ${CONFIG.maxRedirects}.` });
}

function requestUpstream(clientReq, targetUrl, resolvedAddress) {
  return new Promise((resolve, reject) => {
    const transport = targetUrl.protocol === "https:" ? https : http;
    const upstreamReq = transport.request(
      targetUrl,
      {
        method: clientReq.method,
        headers: buildUpstreamHeaders(clientReq),
        lookup: resolvedAddress
          ? (_hostname, _options, callback) => callback(null, resolvedAddress.address, resolvedAddress.family)
          : undefined,
      },
      resolve,
    );

    upstreamReq.setTimeout(30_000, () => {
      upstreamReq.destroy(new Error("Upstream request timed out"));
    });

    upstreamReq.on("error", reject);
    upstreamReq.end();
  });
}

function pipeUpstreamResponse(clientReq, clientRes, upstreamResponse, finalUrl) {
  const headers = {};

  for (const [name, value] of Object.entries(upstreamResponse.headers)) {
    const lowerName = name.toLowerCase();
    if (!HOP_BY_HOP_HEADERS.has(lowerName) && value !== undefined) {
      headers[name] = value;
    }
  }

  headers["x-proxy-final-host"] = finalUrl.hostname;
  headers["x-proxy-by"] = "universal-download-proxy-vps";
  headers["cache-control"] = "no-store";
  headers["access-control-allow-origin"] = "*";
  headers["access-control-expose-headers"] = "content-length, content-range, content-type, content-disposition, accept-ranges, etag, last-modified, x-proxy-final-host";

  clientRes.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.statusMessage || "", headers);

  if (clientReq.method === "HEAD") {
    upstreamResponse.resume();
    clientRes.end();
    return;
  }

  upstreamResponse.pipe(clientRes);
}

function buildUpstreamHeaders(req) {
  const headers = {};

  for (const [name, value] of Object.entries(req.headers)) {
    const lowerName = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowerName) || BLOCKED_REQUEST_HEADERS.has(lowerName)) {
      continue;
    }

    headers[name] = value;
  }

  headers.accept = headers.accept || "*/*";
  headers["user-agent"] = headers["user-agent"] || "universal-download-proxy-vps";

  return headers;
}

function resolveTargetUrl(requestUrl) {
  let raw = requestUrl.searchParams.get("url") || requestUrl.pathname.slice(1);

  if (!raw) {
    return { ok: false, message: "Missing target URL" };
  }

  if (!requestUrl.searchParams.has("url") && requestUrl.search) {
    const params = new URLSearchParams(requestUrl.search);
    params.delete("token");
    const suffix = params.toString();
    if (suffix) {
      raw += `?${suffix}`;
    }
  }

  if (raw.length > CONFIG.maxTargetLength) {
    return { ok: false, message: "Target URL is too long" };
  }

  const decoded = requestUrl.searchParams.has("url") ? raw : safeDecode(raw);
  const normalized = decoded.startsWith("http://") || decoded.startsWith("https://")
    ? decoded
    : `https://${decoded}`;

  let targetUrl;
  try {
    targetUrl = new URL(normalized);
  } catch {
    return { ok: false, message: "Invalid target URL" };
  }

  if (!["http:", "https:"].includes(targetUrl.protocol)) {
    return { ok: false, message: "Only HTTP and HTTPS targets are supported" };
  }

  targetUrl.username = "";
  targetUrl.password = "";

  return { ok: true, url: targetUrl };
}

async function validateTarget(targetUrl) {
  const hostname = targetUrl.hostname.toLowerCase();

  if (!["http:", "https:"].includes(targetUrl.protocol)) {
    return { ok: false, message: "Only HTTP and HTTPS targets are supported" };
  }

  if (CONFIG.blockedHosts.has(hostname)) {
    return { ok: false, message: `Host is blocked: ${hostname}` };
  }

  if (CONFIG.allowedHosts.length > 0 && !CONFIG.allowedHosts.includes(hostname)) {
    return { ok: false, message: `Host is not in ALLOWED_HOSTS: ${hostname}` };
  }

  if (!CONFIG.allowPrivateIps && isPrivateHostname(hostname)) {
    return { ok: false, message: `Private or local targets are blocked: ${hostname}` };
  }

  if (!CONFIG.allowPrivateIps && net.isIP(hostname) === 0) {
    const resolvedResult = await resolvePublicAddresses(hostname);
    if (!resolvedResult.ok) {
      return { ok: false, message: resolvedResult.message };
    }

    const resolved = resolvedResult.records;
    const privateAddress = resolved.find((record) => isPrivateHostname(record.address));
    if (privateAddress) {
      return { ok: false, message: `DNS resolved to private or local address: ${privateAddress.address}` };
    }

    return { ok: true, resolvedAddress: resolved[0] };
  }

  return { ok: true };
}

async function resolvePublicAddresses(hostname) {
  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    if (!records.length) {
      return { ok: false, message: `DNS resolution returned no addresses: ${hostname}` };
    }

    return {
      ok: true,
      records: records.map((record) => ({
        address: record.address,
        family: record.family,
      })),
    };
  } catch (error) {
    return { ok: false, message: `DNS resolution failed: ${hostname}` };
  }
}

function isAuthorized(req, requestUrl) {
  const token = requestUrl.searchParams.get("token") || "";
  const proxyPassword = req.headers["x-proxy-password"] || "";
  const authorization = req.headers.authorization || "";
  const bearer = authorization.toLowerCase().startsWith("bearer ") ? authorization.slice(7).trim() : "";

  return timingSafeStringEqual(token, CONFIG.password)
    || timingSafeStringEqual(String(proxyPassword), CONFIG.password)
    || timingSafeStringEqual(bearer, CONFIG.password)
    || hasValidSession(req);
}

function setSession(res) {
  const expires = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const payload = `${expires}.${randomBytes(16).toString("hex")}`;
  const signature = sign(payload);
  const cookie = `udp_session=${payload}.${signature}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`;
  res.setHeader("set-cookie", cookie);
}

function clearSession(res) {
  res.setHeader("set-cookie", "udp_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
}

function hasValidSession(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  const session = cookies.udp_session;
  if (!session) {
    return false;
  }

  const parts = session.split(".");
  if (parts.length !== 3) {
    return false;
  }

  const [expiresText, nonce, signature] = parts;
  const payload = `${expiresText}.${nonce}`;
  const expires = Number(expiresText);

  return Number.isFinite(expires)
    && expires > Date.now()
    && timingSafeStringEqual(signature, sign(payload));
}

function sign(payload) {
  return createHmac("sha256", CONFIG.secret).update(payload).digest("hex");
}

function getRequestUrl(req) {
  const protocol = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host || `${CONFIG.host}:${CONFIG.port}`;
  return new URL(req.url || "/", `${protocol}://${host}`);
}

function renderHome(req, error = "") {
  const requestUrl = getRequestUrl(req);
  const signedIn = hasValidSession(req);
  const defaultProxyUrl = requestUrl.searchParams.get("url") || "";

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Universal Download Proxy</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #f4f6f8;
      color: #151b23;
    }
    main {
      width: min(760px, calc(100vw - 32px));
      padding: 32px 0;
    }
    .panel {
      border: 1px solid #d0d7de;
      border-radius: 8px;
      background: #ffffff;
      padding: 24px;
      box-shadow: 0 16px 48px rgba(31, 35, 40, 0.08);
    }
    h1 {
      margin: 0 0 16px;
      font-size: 26px;
      letter-spacing: 0;
    }
    form {
      display: grid;
      gap: 14px;
    }
    label {
      display: grid;
      gap: 6px;
      font-weight: 650;
    }
    input, button {
      width: 100%;
      min-height: 44px;
      border-radius: 6px;
      font: inherit;
    }
    input {
      border: 1px solid #d0d7de;
      padding: 0 12px;
      background: #fff;
      color: #151b23;
    }
    button {
      border: 0;
      background: #0969da;
      color: #fff;
      cursor: pointer;
      font-weight: 700;
    }
    .secondary {
      background: #57606a;
    }
    .row {
      display: grid;
      gap: 10px;
      grid-template-columns: 1fr auto;
      align-items: end;
    }
    .row form {
      display: block;
    }
    p {
      color: #57606a;
      margin: 0 0 18px;
    }
    .error {
      color: #cf222e;
      margin-bottom: 14px;
      font-weight: 650;
    }
    code {
      padding: 2px 5px;
      border-radius: 4px;
      background: #eaeef2;
      word-break: break-all;
    }
    @media (max-width: 560px) {
      .row { grid-template-columns: 1fr; }
    }
    @media (prefers-color-scheme: dark) {
      body { background: #0d1117; color: #f0f6fc; }
      .panel { background: #161b22; border-color: #30363d; box-shadow: none; }
      p { color: #8b949e; }
      input { background: #0d1117; border-color: #30363d; color: #f0f6fc; }
      code { background: #21262d; }
      .secondary { background: #6e7681; }
    }
  </style>
</head>
<body>
  <main>
    <div class="panel">
      <div class="row">
        <div>
          <h1>Universal Download Proxy</h1>
          <p>${signedIn ? "已登录。粘贴目标 URL 后即可通过服务器流式下载。" : "先登录，再粘贴目标 URL 进行流式下载。"}</p>
        </div>
        ${signedIn ? '<form method="post" action="/logout"><button class="secondary" type="submit">退出</button></form>' : ""}
      </div>
      ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
      ${signedIn ? renderProxyForm(defaultProxyUrl) : renderLoginForm(requestUrl)}
    </div>
  </main>
</body>
</html>`;
}

function renderLoginForm(requestUrl) {
  const next = requestUrl.searchParams.get("next") || "/";
  return `<form method="post" action="/login">
    <input type="hidden" name="next" value="${escapeHtml(next)}">
    <label>
      访问密码
      <input name="password" type="password" autocomplete="current-password" required autofocus>
    </label>
    <button type="submit">登录</button>
  </form>`;
}

function renderProxyForm(defaultProxyUrl) {
  return `<form id="proxy-form">
    <label>
      目标 URL
      <input id="url" name="url" type="url" value="${escapeHtml(defaultProxyUrl)}" placeholder="https://example.com/file.zip" required autofocus>
    </label>
    <button type="submit">开始下载</button>
  </form>
  <script>
    document.getElementById("proxy-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const url = document.getElementById("url").value.trim();
      const target = new URL("/proxy", location.origin);
      target.searchParams.set("url", url);
      location.href = target.toString();
    });
  </script>`;
}

function sendHtml(res, statusCode, html, extraHeaders = {}) {
  res.writeHead(statusCode, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(html);
}

function sendJson(res, statusCode, data, extraHeaders = {}) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, HEAD, OPTIONS",
    "access-control-allow-headers": "range, if-none-match, if-modified-since, accept, user-agent, authorization, x-proxy-password",
    ...extraHeaders,
  });
  res.end(body);
}

function sendCors(res, statusCode) {
  res.writeHead(statusCode, {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, HEAD, OPTIONS",
    "access-control-allow-headers": "range, if-none-match, if-modified-since, accept, user-agent, authorization, x-proxy-password",
  });
  res.end();
}

function redirect(res, location) {
  res.writeHead(303, { location });
  res.end();
}

function sanitizeNext(value) {
  if (!value || typeof value !== "string") {
    return "/";
  }

  if (!value.startsWith("/") || value.startsWith("//")) {
    return "/";
  }

  return value;
}

async function readBody(req, limit) {
  let body = "";

  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > limit) {
      throw new Error("Request body is too large");
    }
  }

  return body;
}

function parseCookies(cookieHeader) {
  const cookies = {};

  for (const pair of cookieHeader.split(";")) {
    const index = pair.indexOf("=");
    if (index === -1) {
      continue;
    }

    const name = pair.slice(0, index).trim();
    const value = pair.slice(index + 1).trim();
    cookies[name] = value;
  }

  return cookies;
}

function isPrivateHostname(hostname) {
  if (!hostname || hostname.endsWith(".local") || hostname.endsWith(".localhost")) {
    return true;
  }

  const ipVersion = net.isIP(hostname);
  if (ipVersion === 6) {
    const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return normalized === "::1"
      || normalized === "0:0:0:0:0:0:0:1"
      || normalized.startsWith("fc")
      || normalized.startsWith("fd")
      || normalized.startsWith("fe80:");
  }

  if (ipVersion !== 4) {
    return false;
  }

  const nums = hostname.split(".").map(Number);
  const [a, b] = nums;
  return a === 0
    || a === 10
    || a === 127
    || a === 169 && b === 254
    || a === 172 && b >= 16 && b <= 31
    || a === 192 && b === 168
    || a >= 224;
}

function isRedirect(statusCode) {
  return [301, 302, 303, 307, 308].includes(statusCode || 0);
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function parseList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function timingSafeStringEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  const length = Math.max(aBuffer.length, bBuffer.length);
  const paddedA = Buffer.alloc(length);
  const paddedB = Buffer.alloc(length);

  aBuffer.copy(paddedA);
  bBuffer.copy(paddedB);

  return timingSafeEqual(paddedA, paddedB) && aBuffer.length === bBuffer.length;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function loadDotEnv(file = ".env") {
  if (!fs.existsSync(file)) {
    return;
  }

  const content = fs.readFileSync(file, "utf8");
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const index = trimmed.indexOf("=");
    if (index === -1) {
      continue;
    }

    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"'))
      || (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function isMainModule() {
  if (!process.argv[1]) {
    return false;
  }

  return fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1]);
}
