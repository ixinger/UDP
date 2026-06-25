/*
 * Universal Download Proxy for Cloudflare Workers
 *
 * Paste this whole file into the Cloudflare Workers online editor.
 *
 * Required environment variable:
 *   PROXY_PASSWORD = "change-this-password"
 *
 * Optional environment variables:
 *   ALLOW_PRIVATE_IPS = "false"
 *   ALLOWED_HOSTS = ""          // comma-separated whitelist; empty means any public host
 *   EXTRA_BLOCKED_HOSTS = ""    // comma-separated hostnames
 *   GITHUB_PROXY_ENABLED = "true"
 *   GITHUB_TOKEN = ""           // optional, improves GitHub API rate limits
 */

const CONFIG = {
  password: "",
  allowPrivateIps: false,
  allowedHosts: "",
  extraBlockedHosts: "",
  githubProxyEnabled: true,
  githubToken: "",
};

const MAX_REDIRECTS = 8;
const MAX_TARGET_LENGTH = 4096;
const PROXY_SESSION_COOKIE = "udp_session";
const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;
const TRENDING_CACHE_TTL_SECONDS = 24 * 60 * 60;
const TRENDING_LIMIT = 8;
const SEARCH_CACHE_TTL_SECONDS = 6 * 60 * 60;
const SEARCH_LIMIT = 10;
const GITHUB_REPO_CACHE_VERSION = "repo-assets-20260621";

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
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cookie",
  "host",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
]);

const BLOCKED_RESPONSE_HEADERS = new Set([
  "set-cookie",
  "set-cookie2",
]);

const GITHUB_STRIPPED_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "nel",
  "report-to",
  "x-frame-options",
]);

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
]);

const GITHUB_AUTH_PATH_PREFIXES = [
  "/login",
  "/session",
  "/sessions",
  "/signup",
  "/join",
  "/settings",
  "/account",
  "/password_reset",
  "/login/oauth",
];

export default {
  async fetch(request, env) {
    const config = loadConfig(env);
    const requestUrl = new URL(request.url);

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    if (!["GET", "HEAD"].includes(request.method)) {
      return json({ error: "Method not allowed" }, 405);
    }

    if (requestUrl.pathname === "/" && !requestUrl.searchParams.has("url")) {
      return renderHomePage(requestUrl);
    }

    const auth = await authorize(request, requestUrl, config.password);
    if (!auth.ok) {
      if (acceptsHtml(request)) {
        return withCors(renderUnlockPage(requestUrl));
      }

      return json(
        {
          error: "Unauthorized",
          usage: "Pass the password by X-Proxy-Password header, Authorization: Bearer header, or token query parameter.",
        },
        401,
        { "www-authenticate": 'Bearer realm="Universal Download Proxy"' },
      );
    }

    if (auth.sessionCookie && requestUrl.searchParams.has("token") && acceptsHtml(request)) {
      return attachProxySession(withCors(redirectWithoutToken(requestUrl)), auth);
    }

    if (requestUrl.pathname === "/__github_trending") {
      try {
        return attachProxySession(withCors(await getDailyGithubTrending(requestUrl.origin, requestUrl)), auth);
      } catch (error) {
        return json({ error: error.message || "Failed to load GitHub trending" }, 502);
      }
    }

    if (requestUrl.pathname === "/__github_search") {
      return attachProxySession(withCors(await searchGithubRepositories(requestUrl, config)), auth);
    }

    if (requestUrl.pathname === "/__github_repo") {
      return attachProxySession(withCors(await getGithubRepoSummary(requestUrl, config)), auth);
    }

    const targetResult = resolveTargetUrl(requestUrl, request);
    if (!targetResult.ok) {
      return json({ error: targetResult.message }, 400);
    }

    const validation = validateTarget(targetResult.url, config);
    if (!validation.ok) {
      return json({ error: validation.message }, 403);
    }

    if (config.githubProxyEnabled && isGithubAuthTarget(targetResult.url)) {
      return attachProxySession(withCors(renderGithubLoginWarning(requestUrl.origin, targetResult.url)), auth);
    }

    if (config.githubProxyEnabled && request.method === "GET" && isGithubSearchTarget(targetResult.url) && acceptsHtml(request)) {
      return attachProxySession(withCors(renderGithubPortal(requestUrl.origin, targetResult.url.searchParams.get("q") || "")), auth);
    }

    if (config.githubProxyEnabled && request.method === "GET" && isGithubRepoPageTarget(targetResult.url) && acceptsHtml(request)) {
      const repoPath = getGithubRepoPath(targetResult.url);
      const contentPath = targetResult.url.searchParams.get("path") || "";
      return attachProxySession(withCors(renderGithubRepoPage(requestUrl.origin, repoPath.owner, repoPath.repo, contentPath)), auth);
    }

    if (config.githubProxyEnabled && request.method === "GET" && isGithubHomeTarget(targetResult.url)) {
      return attachProxySession(withCors(renderGithubPortal(requestUrl.origin)), auth);
    }

    try {
      const response = await fetchWithValidatedRedirects(request, targetResult.url, config, {
        origin: requestUrl.origin,
        githubProxyEnabled: config.githubProxyEnabled,
      });
      return attachProxySession(withCors(response), auth);
    } catch (error) {
      return json({ error: error.message || "Upstream request failed" }, 502);
    }
  },
};

function loadConfig(env) {
  return {
    password: env.PROXY_PASSWORD || CONFIG.password,
    allowPrivateIps: parseBoolean(env.ALLOW_PRIVATE_IPS, CONFIG.allowPrivateIps),
    allowedHosts: env.ALLOWED_HOSTS || CONFIG.allowedHosts,
    extraBlockedHosts: env.EXTRA_BLOCKED_HOSTS || CONFIG.extraBlockedHosts,
    githubProxyEnabled: parseBoolean(env.GITHUB_PROXY_ENABLED, CONFIG.githubProxyEnabled),
    githubToken: env.GITHUB_TOKEN || CONFIG.githubToken,
  };
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

async function authorize(request, requestUrl, password) {
  if (!password) {
    return { ok: false };
  }

  const token = requestUrl.searchParams.get("token") || "";
  const headerPassword = request.headers.get("x-proxy-password") || "";
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const session = getCookie(request.headers.get("cookie") || "", PROXY_SESSION_COOKIE);

  if ([token, headerPassword, bearer].some((value) => timingSafeEqual(value, password))) {
    return {
      ok: true,
      sessionCookie: await createSessionCookie(password),
    };
  }

  if (session && await verifySessionCookie(session, password)) {
    return { ok: true };
  }

  return { ok: false };
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  const length = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length ^ bBytes.length;

  for (let i = 0; i < length; i += 1) {
    diff |= (aBytes[i] || 0) ^ (bBytes[i] || 0);
  }

  return diff === 0;
}

async function createSessionCookie(password) {
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SECONDS;
  const payload = `v1.${expiresAt}`;
  const signature = await hmacSha256Base64Url(password, payload);
  return `${payload}.${signature}`;
}

async function verifySessionCookie(value, password) {
  const parts = String(value || "").split(".");
  if (parts.length !== 3 || parts[0] !== "v1") {
    return false;
  }

  const expiresAt = Number(parts[1]);
  if (!Number.isFinite(expiresAt) || expiresAt < Math.floor(Date.now() / 1000)) {
    return false;
  }

  const payload = `${parts[0]}.${parts[1]}`;
  const expected = await hmacSha256Base64Url(password, payload);
  return timingSafeEqual(parts[2], expected);
}

async function hmacSha256Base64Url(secret, message) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return base64UrlEncode(new Uint8Array(signature));
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function getCookie(cookieHeader, name) {
  const prefix = `${name}=`;
  return String(cookieHeader || "")
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix))
    ?.slice(prefix.length) || "";
}

function attachProxySession(response, auth) {
  if (!auth.sessionCookie) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.append(
    "set-cookie",
    `${PROXY_SESSION_COOKIE}=${auth.sessionCookie}; Max-Age=${SESSION_MAX_AGE_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`,
  );

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function acceptsHtml(request) {
  const accept = request.headers.get("accept") || "";
  return accept.includes("text/html");
}

function redirectWithoutToken(requestUrl) {
  const cleanUrl = new URL(requestUrl);
  cleanUrl.searchParams.delete("token");

  return new Response(null, {
    status: 302,
    headers: {
      location: `${cleanUrl.pathname}${cleanUrl.search}${cleanUrl.hash}`,
      "cache-control": "no-store",
    },
  });
}

function resolveTargetUrl(proxyUrl, request) {
  let raw = proxyUrl.searchParams.get("url")
    || githubRelativeTargetFromReferer(proxyUrl, request)
    || pathToTarget(proxyUrl.pathname);

  if (!raw) {
    return { ok: false, message: "Missing target URL" };
  }

  if (!proxyUrl.searchParams.has("url") && proxyUrl.search) {
    const params = new URLSearchParams(proxyUrl.search);
    params.delete("token");
    const suffix = params.toString();
    if (suffix) {
      raw += `?${suffix}`;
    }
  }

  if (raw.length > MAX_TARGET_LENGTH) {
    return { ok: false, message: "Target URL is too long" };
  }

  const decoded = proxyUrl.searchParams.has("url") ? raw : safeDecode(raw);
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

function pathToTarget(pathname) {
  const rawPath = pathname.slice(1);
  if (rawPath === "gh") {
    return "github.com";
  }

  if (rawPath.startsWith("gh/")) {
    return `github.com/${rawPath.slice(3)}`;
  }

  if (rawPath.startsWith("raw/")) {
    return `raw.githubusercontent.com/${rawPath.slice(4)}`;
  }

  return rawPath;
}

function githubRelativeTargetFromReferer(proxyUrl, request) {
  if (proxyUrl.searchParams.has("url") || proxyUrl.pathname === "/" || proxyUrl.pathname.startsWith("/gh")) {
    return "";
  }

  const rawPath = proxyUrl.pathname.slice(1);
  if (rawPath.includes(".") && !rawPath.startsWith("_")) {
    return "";
  }

  let refererUrl;
  try {
    refererUrl = new URL(request.headers.get("referer") || "");
  } catch {
    return "";
  }

  if (refererUrl.origin !== proxyUrl.origin) {
    return "";
  }

  let refererTarget;
  try {
    const refererRaw = pathToTarget(refererUrl.pathname);
    refererTarget = new URL(refererRaw.startsWith("http://") || refererRaw.startsWith("https://")
      ? refererRaw
      : `https://${refererRaw}`);
  } catch {
    return "";
  }

  if (!isGithubProxyHost(refererTarget.hostname)) {
    return "";
  }

  return `github.com${proxyUrl.pathname}`;
}

async function fetchWithValidatedRedirects(originalRequest, startUrl, config, proxyContext) {
  let targetUrl = startUrl;

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    const validation = validateTarget(targetUrl, config);
    if (!validation.ok) {
      throw new Error(validation.message);
    }

    const upstreamRequest = new Request(targetUrl, {
      method: originalRequest.method,
      headers: buildUpstreamHeaders(originalRequest),
      redirect: "manual",
      cf: {
        cacheTtl: 0,
        cacheEverything: false,
      },
    });

    const upstreamResponse = await fetch(upstreamRequest);

    if (!isRedirect(upstreamResponse.status)) {
      return buildClientResponse(upstreamResponse, targetUrl, proxyContext);
    }

    const location = upstreamResponse.headers.get("location");
    if (!location) {
      return buildClientResponse(upstreamResponse, targetUrl, proxyContext);
    }

    targetUrl = new URL(location, targetUrl);
    targetUrl.username = "";
    targetUrl.password = "";
  }

  throw new Error(`Too many redirects. Limit is ${MAX_REDIRECTS}.`);
}

function buildUpstreamHeaders(request) {
  const headers = new Headers();

  for (const [name, value] of request.headers) {
    const lowerName = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowerName) || BLOCKED_REQUEST_HEADERS.has(lowerName)) {
      continue;
    }

    if (lowerName === "authorization" || lowerName === "x-proxy-password") {
      continue;
    }

    headers.set(name, value);
  }

  headers.set("accept", request.headers.get("accept") || "*/*");
  headers.set("user-agent", request.headers.get("user-agent") || "universal-download-proxy-worker");

  return headers;
}

function buildClientResponse(upstreamResponse, finalUrl, proxyContext) {
  const headers = new Headers();
  const isGithubTarget = proxyContext.githubProxyEnabled && isGithubProxyHost(finalUrl.hostname);

  for (const [name, value] of upstreamResponse.headers) {
    const lowerName = name.toLowerCase();
    if (
      HOP_BY_HOP_HEADERS.has(lowerName)
      || BLOCKED_RESPONSE_HEADERS.has(lowerName)
      || isGithubTarget && GITHUB_STRIPPED_RESPONSE_HEADERS.has(lowerName)
    ) {
      continue;
    }

    headers.set(name, value);
  }

  headers.set("x-proxy-final-host", finalUrl.hostname);
  headers.set("x-proxy-by", "universal-download-proxy-worker");
  headers.set("cache-control", "no-store");
  headers.set("cdn-cache-control", "no-store");
  headers.set("cloudflare-cdn-cache-control", "no-store");

  let response = new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers,
  });

  if (isGithubTarget) {
    response = rewriteGithubResponse(response, finalUrl, proxyContext.origin);
  }

  return response;
}

function validateTarget(targetUrl, config) {
  const hostname = targetUrl.hostname.toLowerCase();
  const allowedHosts = parseHostList(config.allowedHosts);
  const blockedHosts = new Set([...BLOCKED_HOSTS, ...parseHostList(config.extraBlockedHosts)]);

  if (!["http:", "https:"].includes(targetUrl.protocol)) {
    return { ok: false, message: "Only HTTP and HTTPS targets are supported" };
  }

  if (blockedHosts.has(hostname)) {
    return { ok: false, message: `Host is blocked: ${hostname}` };
  }

  if (
    allowedHosts.length > 0
    && !allowedHosts.includes(hostname)
    && !(config.githubProxyEnabled && isGithubProxyHost(hostname))
  ) {
    return { ok: false, message: `Host is not in ALLOWED_HOSTS: ${hostname}` };
  }

  if (!config.allowPrivateIps && isPrivateHostname(hostname)) {
    return { ok: false, message: `Private or local targets are blocked: ${hostname}` };
  }

  return { ok: true };
}

function isGithubProxyHost(hostname) {
  const host = String(hostname || "").toLowerCase();
  return host === "github.com"
    || host === "www.github.com"
    || host.endsWith(".github.com")
    || host === "githubusercontent.com"
    || host.endsWith(".githubusercontent.com")
    || host === "githubassets.com"
    || host.endsWith(".githubassets.com")
    || host === "githubstatus.com"
    || host.endsWith(".githubstatus.com");
}

function isGithubAuthTarget(targetUrl) {
  if (!isGithubProxyHost(targetUrl.hostname)) {
    return false;
  }

  const path = targetUrl.pathname.toLowerCase();
  return GITHUB_AUTH_PATH_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

function isGithubHomeTarget(targetUrl) {
  const host = targetUrl.hostname.toLowerCase();
  return (host === "github.com" || host === "www.github.com")
    && targetUrl.pathname === "/"
    && !targetUrl.search;
}

function isGithubSearchTarget(targetUrl) {
  const host = targetUrl.hostname.toLowerCase();
  return (host === "github.com" || host === "www.github.com")
    && targetUrl.pathname === "/search";
}

function isGithubRepoPageTarget(targetUrl) {
  const repoPath = getGithubRepoPath(targetUrl);
  if (!repoPath) {
    return false;
  }

  const pathParts = targetUrl.pathname.split("/").filter(Boolean);
  const pathname = targetUrl.pathname.replace(/\/+$/, "");

  return pathname === `/${repoPath.owner}/${repoPath.repo}`
    || pathParts.length === 3 && pathParts[2] === "releases";
}

function getGithubRepoPath(targetUrl) {
  const host = targetUrl.hostname.toLowerCase();
  if (host !== "github.com" && host !== "www.github.com") {
    return null;
  }

  const parts = targetUrl.pathname.split("/").filter(Boolean);
  if (parts.length < 2 || !isSafeGithubPathPart(parts[0]) || !isSafeGithubPathPart(parts[1])) {
    return null;
  }

  return {
    owner: parts[0],
    repo: parts[1],
  };
}

function isSafeGithubPathPart(value) {
  return /^[A-Za-z0-9_.-]+$/.test(value || "");
}

async function getDailyGithubTrending(proxyOrigin, requestUrl) {
  const today = getShanghaiDateString();
  const requestedDate = requestUrl.searchParams.get("date") || today;
  const cacheDate = /^\d{4}-\d{2}-\d{2}$/.test(requestedDate) ? requestedDate : today;
  const cacheKey = new Request(`https://universal-download-proxy.local/cache/github-trending/${cacheDate}`);

  if (typeof caches !== "undefined" && caches.default) {
    const cached = await caches.default.match(cacheKey);
    if (cached) {
      return cached;
    }
  }

  const upstreamResponse = await fetch("https://github.com/trending?since=daily", {
    headers: {
      accept: "text/html,application/xhtml+xml",
      "user-agent": "universal-download-proxy-worker",
    },
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    },
  });

  if (!upstreamResponse.ok) {
    throw new Error(`GitHub Trending responded with ${upstreamResponse.status}`);
  }

  const html = await upstreamResponse.text();
  const data = {
    date: cacheDate,
    source: "https://github.com/trending?since=daily",
    projects: parseGithubTrendingHtml(html, proxyOrigin).slice(0, TRENDING_LIMIT),
  };

  const response = new Response(JSON.stringify(data, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": `public, max-age=${TRENDING_CACHE_TTL_SECONDS}`,
      "x-robots-tag": "noindex, nofollow",
    },
  });

  if (typeof caches !== "undefined" && caches.default) {
    await caches.default.put(cacheKey, response.clone());
  }

  return response;
}

function getShanghaiDateString() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${values.year}-${values.month}-${values.day}`;
}

async function searchGithubRepositories(requestUrl, config) {
  const query = (requestUrl.searchParams.get("q") || "").trim().slice(0, 200);
  if (!query) {
    return jsonResponse({ query: "", projects: [] });
  }

  const cacheKey = new Request(`https://universal-download-proxy.local/cache/github-search/${encodeURIComponent(query.toLowerCase())}`);
  if (typeof caches !== "undefined" && caches.default) {
    const cached = await caches.default.match(cacheKey);
    if (cached) {
      return cached;
    }
  }

  const searchUrl = new URL("https://api.github.com/search/repositories");
  searchUrl.searchParams.set("q", query);
  searchUrl.searchParams.set("sort", "stars");
  searchUrl.searchParams.set("order", "desc");
  searchUrl.searchParams.set("per_page", String(SEARCH_LIMIT));

  const headers = new Headers({
    accept: "application/vnd.github+json",
    "user-agent": "universal-download-proxy-worker",
    "x-github-api-version": "2022-11-28",
  });

  if (config.githubToken) {
    headers.set("authorization", `Bearer ${config.githubToken}`);
  }

  const upstreamResponse = await fetch(searchUrl, {
    headers,
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    },
  });

  if (!upstreamResponse.ok) {
    const retryAfter = upstreamResponse.headers.get("retry-after");
    return jsonResponse(
      {
        query,
        projects: [],
        error: retryAfter
          ? `GitHub search is rate limited. Try again after ${retryAfter} seconds.`
          : `GitHub search responded with ${upstreamResponse.status}.`,
      },
      upstreamResponse.status === 403 || upstreamResponse.status === 429 ? 429 : 502,
      { "cache-control": "no-store" },
    );
  }

  const data = await upstreamResponse.json();
  const response = jsonResponse(
    {
      query,
      projects: normalizeGithubSearchItems(data.items || [], requestUrl.origin),
    },
    200,
    { "cache-control": `public, max-age=${SEARCH_CACHE_TTL_SECONDS}` },
  );

  if (typeof caches !== "undefined" && caches.default) {
    await caches.default.put(cacheKey, response.clone());
  }

  return response;
}

function normalizeGithubSearchItems(items, proxyOrigin) {
  return items.slice(0, SEARCH_LIMIT)
    .filter((item) => item && item.full_name)
    .map((item) => ({
      name: item.full_name,
      description: item.description || "",
      language: item.language || "",
      stars: formatCount(item.stargazers_count),
      forks: formatCount(item.forks_count),
      updatedAt: item.updated_at ? item.updated_at.slice(0, 10) : "",
      url: `${proxyOrigin}/gh/${item.full_name}`,
    }));
}

function formatCount(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number.toLocaleString("en-US") : "";
}

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "x-robots-tag": "noindex, nofollow",
      ...headers,
    },
  });
}

async function getGithubRepoSummary(requestUrl, config) {
  const owner = (requestUrl.searchParams.get("owner") || "").trim();
  const repo = (requestUrl.searchParams.get("repo") || "").trim();
  const contentPath = normalizeGithubContentPath(requestUrl.searchParams.get("path") || "");
  if (!isSafeGithubPathPart(owner) || !isSafeGithubPathPart(repo)) {
    return jsonResponse({ error: "Invalid GitHub repository path" }, 400);
  }

  const cacheKey = new Request(`https://universal-download-proxy.local/cache/github-repo/${GITHUB_REPO_CACHE_VERSION}/${owner}/${repo}/${encodeURIComponent(contentPath)}`);
  if (typeof caches !== "undefined" && caches.default) {
    const cached = await caches.default.match(cacheKey);
    if (cached) {
      return cached;
    }
  }

  const contentsPath = encodeURIComponentContentPath(contentPath);
  const contentsUrl = contentsPath
    ? `https://api.github.com/repos/${owner}/${repo}/contents/${contentsPath}?per_page=100`
    : `https://api.github.com/repos/${owner}/${repo}/contents?per_page=100`;

  const [repoInfo, readme, releases, contents] = await Promise.all([
    fetchGithubJson(`https://api.github.com/repos/${owner}/${repo}`, config),
    fetchGithubJson(`https://api.github.com/repos/${owner}/${repo}/readme`, config, true),
    fetchGithubJson(`https://api.github.com/repos/${owner}/${repo}/releases?per_page=5`, config, true),
    fetchGithubJson(contentsUrl, config, true),
  ]);

  if (!repoInfo.ok) {
    const fallback = await getGithubRepoFallback(owner, repo, contentPath, requestUrl.origin);
    if (fallback.ok) {
      const response = jsonResponse({
        ...fallback.data,
        warning: repoInfo.error || "GitHub API unavailable. Showing fallback data.",
      }, 200, { "cache-control": "public, max-age=900" });

      if (typeof caches !== "undefined" && caches.default) {
        await caches.default.put(cacheKey, response.clone());
      }

      return response;
    }

    return jsonResponse({ error: repoInfo.error || fallback.error || "Repository not found" }, repoInfo.status || 502);
  }

  const defaultBranch = repoInfo.data.default_branch || "main";
  let readmeText = readme.ok && readme.data.download_url
    ? await fetchGithubText(readme.data.download_url, config)
    : "";
  let readmeSource = readmeText ? "api" : "";

  if (!readmeText) {
    readmeText = await fetchFallbackReadme(owner, repo, defaultBranch);
    readmeSource = readmeText ? "raw-fallback" : "";
  }
  if (!readmeText) {
    const readmeFallback = await fetchFallbackReadmeFromHtml(owner, repo);
    readmeText = readmeFallback.text;
    readmeSource = readmeText ? readmeFallback.source : "";
  }

  const rawReleases = releases.ok ? releases.data : [];
  let releaseItems = normalizeGithubReleases(rawReleases, requestUrl.origin, owner, repo);
  let releasesSource = releaseItems.length ? "api" : "";
  if (releaseItems.length) {
    const apiAssetCount = await fillReleaseAssetsFromApi(rawReleases, releaseItems, config, requestUrl.origin);
    const htmlAssetCount = await fillExpandedReleaseAssets(owner, repo, requestUrl.origin, releaseItems);
    ensureSourceCodeAssets(owner, repo, requestUrl.origin, releaseItems);
    if (apiAssetCount || htmlAssetCount) {
      releasesSource = `${releasesSource}+assets`;
    }
  }
  if (!releaseItems.length) {
    releaseItems = await fetchFallbackReleases(owner, repo, requestUrl.origin);
    releasesSource = releaseItems.length ? "html-fallback" : "";
  }

  let contentItems = normalizeGithubContents(contents.ok ? contents.data : [], requestUrl.origin, owner, repo, defaultBranch);
  let contentsSource = contentItems.length ? "api" : "";
  if (!contentItems.length) {
    const fallbackContents = await fetchFallbackContents(owner, repo, defaultBranch, contentPath, requestUrl.origin);
    contentItems = fallbackContents.items;
    contentsSource = contentItems.length ? fallbackContents.source : "";
  }

  const data = {
    repo: normalizeGithubRepoInfo(repoInfo.data, requestUrl.origin),
    readme: readmeText.slice(0, 60000),
    releases: releaseItems,
    path: contentPath,
    contents: contentItems,
    sources: {
      readme: readmeSource,
      releases: releasesSource,
      contents: contentsSource,
    },
  };

  const response = jsonResponse(data, 200, { "cache-control": "public, max-age=1800" });
  if (typeof caches !== "undefined" && caches.default) {
    await caches.default.put(cacheKey, response.clone());
  }

  return response;
}

async function fetchGithubJson(url, config, allowNotFound = false) {
  const response = await fetch(url, {
    headers: buildGithubApiHeaders(config),
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    },
  });

  if (!response.ok) {
    if (allowNotFound && response.status === 404) {
      return { ok: false, status: 404, data: null };
    }

    return {
      ok: false,
      status: response.status === 403 || response.status === 429 ? 429 : response.status,
      error: response.status === 403 || response.status === 429
        ? "GitHub API 限流，已尝试使用备用数据源。若频繁出现，请添加 Worker Secret GITHUB_TOKEN。"
        : `GitHub API responded with ${response.status}.`,
    };
  }

  return { ok: true, status: response.status, data: await response.json() };
}

async function fetchGithubText(url, config) {
  const response = await fetch(url, {
    headers: buildGithubApiHeaders(config),
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    },
  });

  return response.ok ? response.text() : "";
}

function buildGithubApiHeaders(config) {
  const headers = new Headers({
    accept: "application/vnd.github+json",
    "user-agent": "universal-download-proxy-worker",
    "x-github-api-version": "2022-11-28",
  });

  if (config.githubToken) {
    headers.set("authorization", `Bearer ${config.githubToken}`);
  }

  return headers;
}

function normalizeGithubRepoInfo(repo, proxyOrigin) {
  return {
    fullName: repo.full_name || "",
    description: repo.description || "",
    language: repo.language || "",
    stars: formatCount(repo.stargazers_count),
    forks: formatCount(repo.forks_count),
    watchers: formatCount(repo.watchers_count),
    license: repo.license && repo.license.spdx_id ? repo.license.spdx_id : "",
    defaultBranch: repo.default_branch || "main",
    updatedAt: repo.updated_at ? repo.updated_at.slice(0, 10) : "",
    homepage: repo.homepage || "",
    proxyUrl: `${proxyOrigin}/gh/${repo.full_name}`,
    rawBaseUrl: `${proxyOrigin}/raw/${repo.full_name}/${repo.default_branch || "main"}`,
  };
}

function normalizeGithubReleases(releases, proxyOrigin, owner = "", repo = "") {
  return (Array.isArray(releases) ? releases : []).slice(0, 5).map((release) => ({
    name: release.name || release.tag_name || "",
    tag: release.tag_name || "",
    publishedAt: release.published_at ? release.published_at.slice(0, 10) : "",
    body: release.body ? String(release.body).slice(0, 1200) : "",
    url: `${proxyOrigin}/gh/${release.html_url ? githubPathFromUrl(release.html_url) : ""}`,
    assets: normalizeGithubReleaseAssetItems(release.assets, proxyOrigin),
  }));
}

function normalizeGithubReleaseAssetItems(assets, proxyOrigin) {
  return (Array.isArray(assets) ? assets : []).slice(0, 10)
    .map((asset) => ({
      name: asset.name || "",
      size: formatBytes(asset.size),
      url: proxifyExternalUrl(asset.browser_download_url || "", proxyOrigin),
    }))
    .filter((asset) => asset.name && asset.url);
}

function normalizeGithubContents(contents, proxyOrigin, owner, repo, branch) {
  return (Array.isArray(contents) ? contents : []).slice(0, 80).map((item) => ({
    name: item.name || "",
    type: item.type || "",
    size: item.type === "file" ? formatBytes(item.size) : "",
    url: item.type === "file"
      ? `${proxyOrigin}/raw/${owner}/${repo}/${branch}/${item.path}`
      : `${proxyOrigin}/gh/${owner}/${repo}?path=${encodeURIComponent(item.path)}`,
  }));
}

async function getGithubRepoFallback(owner, repo, contentPath, proxyOrigin) {
  const repoUrl = `https://github.com/${owner}/${repo}${contentPath ? `/tree/HEAD/${contentPath}` : ""}`;
  const response = await fetch(repoUrl, {
    headers: {
      accept: "text/html,application/xhtml+xml",
      "user-agent": "universal-download-proxy-worker",
    },
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    },
  });

  if (!response.ok) {
    return { ok: false, error: `GitHub fallback responded with ${response.status}.` };
  }

  const html = await response.text();
  const repoInfo = parseGithubRepoHtml(html, owner, repo, proxyOrigin);
  const branch = repoInfo.defaultBranch || "main";
  const readme = await fetchFallbackReadme(owner, repo, branch);
  const contents = parseGithubDirectoryHtml(html, proxyOrigin, owner, repo, branch);
  const releases = await fetchFallbackReleases(owner, repo, proxyOrigin);

  return {
    ok: true,
    data: {
      repo: repoInfo,
      readme,
      releases,
      path: contentPath,
      contents,
    },
  };
}

async function fetchFallbackContents(owner, repo, branch, contentPath, proxyOrigin) {
  const urls = [];
  if (contentPath) {
    urls.push(`https://github.com/${owner}/${repo}/tree/${encodeURIComponent(branch)}/${contentPath}`);
    urls.push(`https://github.com/${owner}/${repo}/tree/HEAD/${contentPath}`);
  } else {
    urls.push(`https://github.com/${owner}/${repo}`);
    urls.push(`https://github.com/${owner}/${repo}/tree/${encodeURIComponent(branch)}`);
  }

  for (const url of urls) {
    const response = await fetch(url, {
      headers: {
        accept: "text/html,application/xhtml+xml",
        "user-agent": "universal-download-proxy-worker",
      },
      cf: {
        cacheTtl: 0,
        cacheEverything: false,
      },
    });

    if (response.ok) {
      const items = parseGithubDirectoryHtml(await response.text(), proxyOrigin, owner, repo, branch);
      if (items.length) {
        return { source: "html-fallback", items };
      }
    }
  }

  return { source: "", items: [] };
}

function parseGithubRepoHtml(html, owner, repo, proxyOrigin) {
  const fullName = `${owner}/${repo}`;
  const description = cleanText(
    extractFirstMatch(html, /<meta\s+name="description"\s+content="([^"]*)"/i)
      || extractFirstMatch(html, /<meta\s+property="og:description"\s+content="([^"]*)"/i),
  );
  const defaultBranch = cleanText(
    extractFirstMatch(html, /"defaultBranch"\s*:\s*"([^"]+)"/i)
      || extractFirstMatch(html, /data-default-branch="([^"]+)"/i)
      || "main",
  );

  return {
    fullName,
    description,
    language: "",
    stars: "",
    forks: "",
    watchers: "",
    license: "",
    defaultBranch,
    updatedAt: "",
    homepage: "",
    proxyUrl: `${proxyOrigin}/gh/${fullName}`,
    rawBaseUrl: `${proxyOrigin}/raw/${fullName}/${defaultBranch}`,
  };
}

function parseGithubDirectoryHtml(html, proxyOrigin, owner, repo, branch) {
  const jsonItems = parseGithubDirectoryJsonPayload(html, proxyOrigin, owner, repo, branch);
  if (jsonItems.length) {
    return jsonItems;
  }

  const links = [...html.matchAll(/<a[^>]+href="\/([^"?#]+)"[^>]*>([\s\S]*?)<\/a>/gi)];
  const seen = new Set();
  const prefixBlob = `${owner}/${repo}/blob/`;
  const prefixTree = `${owner}/${repo}/tree/`;
  const items = [];

  for (const match of links) {
    const hrefPath = safeDecode(match[1]);
    let type = "";
    let itemPath = "";

    if (hrefPath.startsWith(prefixBlob)) {
      type = "file";
      itemPath = hrefPath.slice(prefixBlob.length).split("/").slice(1).join("/");
    } else if (hrefPath.startsWith(prefixTree)) {
      type = "dir";
      itemPath = hrefPath.slice(prefixTree.length).split("/").slice(1).join("/");
    } else {
      continue;
    }

    itemPath = normalizeGithubContentPath(itemPath);
    if (!itemPath || seen.has(`${type}:${itemPath}`)) {
      continue;
    }

    seen.add(`${type}:${itemPath}`);
    const name = itemPath.split("/").pop();
    items.push({
      name,
      type,
      size: "",
      url: type === "file"
        ? `${proxyOrigin}/raw/${owner}/${repo}/${branch}/${itemPath}`
        : `${proxyOrigin}/gh/${owner}/${repo}?path=${encodeURIComponent(itemPath)}`,
    });

    if (items.length >= 80) {
      break;
    }
  }

  return items;
}

function parseGithubDirectoryJsonPayload(html, proxyOrigin, owner, repo, branch) {
  const decoded = decodeHtmlEntities(html);
  const pattern = /"path"\s*:\s*"([^"]+)"\s*,\s*"contentType"\s*:\s*"(file|directory|dir)"/gi;
  const seen = new Set();
  const items = [];

  for (const match of decoded.matchAll(pattern)) {
    const itemPath = normalizeGithubContentPath(match[1]);
    if (!itemPath || seen.has(itemPath)) {
      continue;
    }

    seen.add(itemPath);
    const type = match[2] === "file" ? "file" : "dir";
    items.push({
      name: itemPath.split("/").pop(),
      type,
      size: "",
      url: type === "file"
        ? `${proxyOrigin}/raw/${owner}/${repo}/${branch}/${itemPath}`
        : `${proxyOrigin}/gh/${owner}/${repo}?path=${encodeURIComponent(itemPath)}`,
    });

    if (items.length >= 80) {
      break;
    }
  }

  return items;
}

async function fetchFallbackReadme(owner, repo, branch) {
  const names = ["README.md", "README.MD", "README", "readme.md"];
  for (const name of names) {
    const response = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${name}`, {
      headers: {
        accept: "text/plain,*/*",
        "user-agent": "universal-download-proxy-worker",
      },
      cf: {
        cacheTtl: 0,
        cacheEverything: false,
      },
    });

    if (response.ok) {
      return (await response.text()).slice(0, 60000);
    }
  }

  return "";
}

async function fetchFallbackReadmeFromHtml(owner, repo) {
  const response = await fetch(`https://github.com/${owner}/${repo}`, {
    headers: {
      accept: "text/html,application/xhtml+xml",
      "user-agent": "universal-download-proxy-worker",
    },
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    },
  });

  if (!response.ok) {
    return { source: "", text: "" };
  }

  const html = await response.text();
  const readme = extractFirstMatch(html, /<article[^>]+class="[^"]*markdown-body[^"]*"[^>]*>([\s\S]*?)<\/article>/i)
    || extractFirstMatch(html, /<div[^>]+id="readme"[^>]*>[\s\S]*?<div[^>]+class="[^"]*markdown-body[^"]*"[^>]*>([\s\S]*?)<\/div>\s*<\/div>/i);

  if (!readme) {
    return { source: "", text: "" };
  }

  return {
    source: "html-readme-fallback",
    text: htmlToMarkdownish(readme).slice(0, 60000),
  };
}

function htmlToMarkdownish(html) {
  return decodeHtmlEntities(String(html || "")
    .replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, "\n# $1\n")
    .replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, "\n## $1\n")
    .replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, "\n### $1\n")
    .replace(/<br\s*\/?\s*>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<li[^>]*>/gi, "\n- ")
    .replace(/<\/li>/gi, "")
    .replace(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, "[$2]($1)")
    .replace(/<img\s+[^>]*src=["']([^"']+)["'][^>]*alt=["']([^"']*)["'][^>]*>/gi, "![$2]($1)")
    .replace(/<img\s+[^>]*alt=["']([^"']*)["'][^>]*src=["']([^"']+)["'][^>]*>/gi, "![$1]($2)")
    .replace(/<img\s+[^>]*src=["']([^"']+)["'][^>]*>/gi, "![]($1)")
    .replace(/<pre[^>]*><code[^>]*>([\s\S]*?)<\/code><\/pre>/gi, "\n```\n$1\n```\n")
    .replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, "`$1`")
    .replace(/<[^>]+>/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim());
}

async function fetchFallbackReleases(owner, repo, proxyOrigin) {
  const atomReleases = await fetchFallbackReleasesAtom(owner, repo, proxyOrigin);
  if (atomReleases.length) {
    const htmlAssets = await fetchFallbackReleasesHtml(owner, repo, proxyOrigin);
    mergeReleaseAssets(atomReleases, htmlAssets);
    await fillExpandedReleaseAssets(owner, repo, proxyOrigin, atomReleases);
    ensureSourceCodeAssets(owner, repo, proxyOrigin, atomReleases);
    return atomReleases;
  }

  const htmlReleases = await fetchFallbackReleasesHtml(owner, repo, proxyOrigin);
  await fillExpandedReleaseAssets(owner, repo, proxyOrigin, htmlReleases);
  ensureSourceCodeAssets(owner, repo, proxyOrigin, htmlReleases);
  return htmlReleases;
}

async function fetchFallbackReleasesAtom(owner, repo, proxyOrigin) {
  const response = await fetch(`https://github.com/${owner}/${repo}/releases.atom`, {
    headers: {
      accept: "application/atom+xml,text/xml,*/*",
      "user-agent": "universal-download-proxy-worker",
    },
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    },
  });

  if (!response.ok) {
    return [];
  }

  return parseGithubReleasesAtom(await response.text(), proxyOrigin, owner, repo);
}

function parseGithubReleasesAtom(xml, proxyOrigin, owner, repo) {
  const entries = [...String(xml || "").matchAll(/<entry>([\s\S]*?)<\/entry>/gi)];
  return entries.slice(0, 5).map((entryMatch) => {
    const entry = entryMatch[1];
    const title = cleanText(extractFirstMatch(entry, /<title>([\s\S]*?)<\/title>/i));
    const link = extractFirstMatch(entry, /<link[^>]+href="([^"]+)"/i);
    const updated = cleanText(extractFirstMatch(entry, /<updated>([\s\S]*?)<\/updated>/i));
    const content = extractFirstMatch(entry, /<content[^>]*>([\s\S]*?)<\/content>/i);
    const tag = extractReleaseTagFromUrl(link) || title;

    return {
      name: title || tag,
      tag,
      publishedAt: updated ? updated.slice(0, 10) : "",
      body: htmlToMarkdownish(content || ""),
      url: `${proxyOrigin}/gh/${owner}/${repo}/releases/tag/${encodeURIComponent(tag)}`,
      assets: [],
    };
  }).filter((release) => release.tag);
}

function extractReleaseTagFromUrl(value) {
  try {
    const url = new URL(value);
    const marker = "/releases/tag/";
    const index = url.pathname.indexOf(marker);
    return index === -1 ? "" : safeDecode(url.pathname.slice(index + marker.length));
  } catch {
    return "";
  }
}

async function fetchFallbackReleasesHtml(owner, repo, proxyOrigin) {
  const response = await fetch(`https://github.com/${owner}/${repo}/releases`, {
    headers: {
      accept: "text/html,application/xhtml+xml",
      "user-agent": "universal-download-proxy-worker",
    },
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    },
  });

  if (!response.ok) {
    return [];
  }

  return parseGithubReleasesHtml(await response.text(), proxyOrigin, owner, repo);
}

function mergeReleaseAssets(targetReleases, assetReleases) {
  for (const assetRelease of assetReleases) {
    const target = targetReleases.find((release) => release.tag === assetRelease.tag);
    if (target && !target.assets.length) {
      target.assets = assetRelease.assets;
    }
  }
}

async function fillReleaseAssetsFromApi(rawReleases, releases, config, proxyOrigin) {
  let filledCount = 0;
  for (const release of releases.slice(0, 5)) {
    if (hasDownloadAsset(release)) {
      continue;
    }

    const rawRelease = (Array.isArray(rawReleases) ? rawReleases : [])
      .find((item) => item && item.tag_name === release.tag);
    if (!rawRelease || !rawRelease.assets_url) {
      continue;
    }

    const assetsResponse = await fetchGithubJson(rawRelease.assets_url, config, true);
    if (!assetsResponse.ok || !Array.isArray(assetsResponse.data)) {
      continue;
    }

    filledCount += mergeReleaseAssetList(
      release,
      normalizeGithubReleaseAssetItems(assetsResponse.data, proxyOrigin),
    );
  }

  return filledCount;
}

async function fillExpandedReleaseAssets(owner, repo, proxyOrigin, releases) {
  let filledCount = 0;
  for (const release of releases.slice(0, 5)) {
    if (hasDownloadAsset(release)) {
      continue;
    }

    const response = await fetch(`https://github.com/${owner}/${repo}/releases/expanded_assets/${encodeGithubPath(release.tag)}`, {
      headers: {
        accept: "text/html,*/*",
        "user-agent": "universal-download-proxy-worker",
      },
      cf: {
        cacheTtl: 0,
        cacheEverything: false,
      },
    });

    if (!response.ok) {
      continue;
    }

    const assets = parseExpandedReleaseAssets(await response.text(), proxyOrigin, owner, repo, release.tag);
    if (assets.length) {
      filledCount += mergeReleaseAssetList(release, assets);
    }
  }

  return filledCount;
}

function parseExpandedReleaseAssets(html, proxyOrigin, owner, repo, tag) {
  const encodedTag = encodeGithubPath(tag);
  const seen = new Set();
  const assets = [];
  const addAsset = (asset) => {
    const key = asset.url || asset.name;
    if (!asset.name || !asset.url || seen.has(key)) {
      return;
    }

    seen.add(key);
    assets.push(asset);
  };
  const pattern = new RegExp(`href="(?:https:\\/\\/github\\.com)?\\/${escapeRegExp(owner)}\\/${escapeRegExp(repo)}\\/releases\\/download\\/(?:${escapeRegExp(tag)}|${escapeRegExp(encodedTag)})\\/([^"]+)"`, "gi");

  for (const match of html.matchAll(pattern)) {
    const filePath = safeDecode(match[1]);
    const fileName = filePath.split("/").pop();
    if (!fileName) {
      continue;
    }

    addAsset({
      name: fileName,
      size: extractAssetSizeNearLink(html, match.index || 0),
      url: `${proxyOrigin}/github.com/${owner}/${repo}/releases/download/${encodeURIComponent(tag)}/${filePath.split("/").map((part) => encodeURIComponent(part)).join("/")}`,
    });

    if (assets.length >= 12) {
      break;
    }
  }

  const archivePattern = new RegExp(`href="(?:https:\\/\\/github\\.com)?\\/${escapeRegExp(owner)}\\/${escapeRegExp(repo)}\\/archive\\/refs\\/tags\\/([^"]+?\\.(?:zip|tar\\.gz))"`, "gi");
  for (const match of html.matchAll(archivePattern)) {
    const archivePath = safeDecode(match[1]);
    if (!archivePath.startsWith(`${tag}.`) && !archivePath.startsWith(`${tag}/`)) {
      continue;
    }

    const extension = archivePath.endsWith(".tar.gz") ? "tar.gz" : "zip";
    addAsset({
      name: `Source code (${extension})`,
      size: "",
      url: `${proxyOrigin}/github.com/${owner}/${repo}/archive/refs/tags/${archivePath.split("/").map((part) => encodeURIComponent(part)).join("/")}`,
    });

    if (assets.length >= 12) {
      break;
    }
  }

  return assets;
}

function hasDownloadAsset(release) {
  return (release.assets || []).some((asset) => asset && asset.name && !isSourceCodeAsset(asset));
}

function isSourceCodeAsset(asset) {
  return /^Source code \((?:zip|tar\.gz)\)$/i.test(asset && asset.name || "");
}

function mergeReleaseAssetList(release, assets) {
  release.assets = Array.isArray(release.assets) ? release.assets : [];
  const seen = new Set(release.assets.map((asset) => asset.url || asset.name));
  let addedCount = 0;

  for (const asset of assets || []) {
    const key = asset && (asset.url || asset.name);
    if (!key || seen.has(key) || release.assets.length >= 12) {
      continue;
    }

    seen.add(key);
    release.assets.push(asset);
    addedCount += 1;
  }

  return addedCount;
}

function ensureSourceCodeAssets(owner, repo, proxyOrigin, releases) {
  for (const release of releases || []) {
    mergeReleaseAssetList(release, buildSourceCodeAssets(owner, repo, release.tag, proxyOrigin));
  }
}

function buildSourceCodeAssets(owner, repo, tag, proxyOrigin) {
  if (!owner || !repo || !tag) {
    return [];
  }

  const tagPath = encodeGithubPath(tag);
  return [
    {
      name: "Source code (zip)",
      size: "",
      url: `${proxyOrigin}/github.com/${owner}/${repo}/archive/refs/tags/${tagPath}.zip`,
    },
    {
      name: "Source code (tar.gz)",
      size: "",
      url: `${proxyOrigin}/github.com/${owner}/${repo}/archive/refs/tags/${tagPath}.tar.gz`,
    },
  ];
}

function encodeGithubPath(value) {
  return String(value || "").split("/").map((part) => encodeURIComponent(part)).join("/");
}

function extractAssetSizeNearLink(html, index) {
  const nearby = html.slice(index, index + 600);
  return cleanText(extractFirstMatch(nearby, /(\d+(?:\.\d+)?\s*(?:B|KB|MB|GB))/i));
}

function parseGithubReleasesHtml(html, proxyOrigin, owner, repo) {
  const releaseMatches = [...html.matchAll(new RegExp(`<a[^>]+href="/${escapeRegExp(owner)}/${escapeRegExp(repo)}/releases/tag/([^"]+)"[^>]*>([\\s\\S]*?)<\\/a>`, "gi"))];
  const tags = [];
  const seenTags = new Set();

  for (const match of releaseMatches) {
    const tag = safeDecode(match[1]);
    if (!tag || seenTags.has(tag)) {
      continue;
    }

    seenTags.add(tag);
    tags.push({
      name: cleanText(match[2]) || tag,
      tag,
      publishedAt: "",
      body: "",
      url: `${proxyOrigin}/gh/${owner}/${repo}/releases/tag/${encodeURIComponent(tag)}`,
      assets: [],
    });

    if (tags.length >= 5) {
      break;
    }
  }

  const assetMatches = [...html.matchAll(new RegExp(`href="/${escapeRegExp(owner)}/${escapeRegExp(repo)}/releases/download/([^/"]+)/([^"]+)"[^>]*>(?:([\\s\\S]*?)<\\/a>)?`, "gi"))];
  for (const match of assetMatches) {
    const tag = safeDecode(match[1]);
    const fileName = cleanText(match[3] || "") || safeDecode(match[2]);
    let release = tags.find((item) => item.tag === tag);
    if (!release) {
      release = {
        name: tag,
        tag,
        publishedAt: "",
        body: "",
        url: `${proxyOrigin}/gh/${owner}/${repo}/releases/tag/${encodeURIComponent(tag)}`,
        assets: [],
      };
      tags.push(release);
    }

    if (release.assets.length < 8) {
      const encodedFile = match[2].split("/").map((part) => encodeURIComponent(safeDecode(part))).join("/");
      release.assets.push({
        name: fileName,
        size: "",
        url: `${proxyOrigin}/github.com/${owner}/${repo}/releases/download/${encodeURIComponent(tag)}/${encodedFile}`,
      });
    }
  }

  return tags.slice(0, 5);
}

function escapeRegExp(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeGithubContentPath(value) {
  return String(value || "")
    .replace(/^\/+|\/+$/g, "")
    .split("/")
    .filter((part) => isSafeGithubPathPart(part))
    .join("/");
}

function encodeURIComponentContentPath(path) {
  return normalizeGithubContentPath(path)
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
}

function githubPathFromUrl(value) {
  try {
    const url = new URL(value);
    return url.hostname.endsWith("github.com") ? url.pathname.replace(/^\/+/, "") : "";
  } catch {
    return "";
  }
}

function proxifyExternalUrl(value, proxyOrigin) {
  try {
    const url = new URL(value);
    return `${proxyOrigin}/${url.hostname}${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "";
  }
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "";
  }

  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function parseGithubTrendingHtml(html, proxyOrigin) {
  const articles = html.match(/<article[\s\S]*?<\/article>/gi) || [];

  return articles
    .map((article) => {
      const path = extractFirstMatch(article, /<h2[\s\S]*?<a[^>]+href="([^"]+)"/i);
      if (!path || !/^\/[^/]+\/[^/]+/.test(path)) {
        return null;
      }

      const repoPath = cleanText(path).replace(/^\//, "");
      const description = cleanText(extractFirstMatch(article, /<p[^>]*>([\s\S]*?)<\/p>/i));
      const language = cleanText(extractFirstMatch(article, /itemprop="programmingLanguage"[^>]*>([\s\S]*?)<\/span>/i));
      const stars = cleanText(extractFirstMatch(article, /href="[^"]+\/stargazers"[^>]*>([\s\S]*?)<\/a>/i));
      const forks = cleanText(extractFirstMatch(article, /href="[^"]+\/forks"[^>]*>([\s\S]*?)<\/a>/i));
      const todayStars = cleanText(extractFirstMatch(article, /([\d,]+\s+stars?\s+today)/i));

      return {
        name: repoPath,
        description,
        language,
        stars,
        forks,
        todayStars,
        url: `${proxyOrigin}/gh/${repoPath}`,
      };
    })
    .filter(Boolean);
}

function extractFirstMatch(value, pattern) {
  const match = String(value || "").match(pattern);
  return match ? match[1] : "";
}

function cleanText(value) {
  return decodeHtmlEntities(String(value || "")
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim());
}

function decodeHtmlEntities(value) {
  return String(value || "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'")
    .replace(/&#x2F;/g, "/");
}

function rewriteGithubResponse(response, finalUrl, proxyOrigin) {
  const contentType = response.headers.get("content-type") || "";
  const headers = new Headers(response.headers);
  headers.set("x-proxy-github-mode", "mirror");
  headers.delete("content-length");

  if (contentType.includes("text/html")) {
    const htmlResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });

    return new HTMLRewriter()
      .on("body", new GithubWarningInjector())
      .on("[href]", new GithubAttributeRewriter("href", finalUrl, proxyOrigin))
      .on("[src]", new GithubAttributeRewriter("src", finalUrl, proxyOrigin))
      .on("[action]", new GithubAttributeRewriter("action", finalUrl, proxyOrigin))
      .on("[poster]", new GithubAttributeRewriter("poster", finalUrl, proxyOrigin))
      .on("[srcset]", new GithubSrcsetRewriter(finalUrl, proxyOrigin))
      .on("meta[content]", new GithubMetaRefreshRewriter(finalUrl, proxyOrigin))
      .on("[style]", new GithubStyleAttributeRewriter(finalUrl, proxyOrigin))
      .transform(htmlResponse);
  }

  if (contentType.includes("text/css")) {
    return rewriteTextBody(response, headers, (text) => rewriteCssUrls(text, finalUrl, proxyOrigin));
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

class GithubWarningInjector {
  element(element) {
    element.prepend(
      `<div style="position:fixed;right:12px;bottom:12px;z-index:2147483647;max-width:min(420px,calc(100vw - 24px));padding:8px 10px;border-radius:10px;background:rgba(255,243,205,.96);color:#5f4300;border:1px solid #f0d98c;font:13px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.16);pointer-events:none;">
        ⚠️ GitHub 代理模式：只浏览公开页面和下载文件，不要登录或输入密码、Token、2FA。
      </div>`,
      { html: true },
    );
  }
}

class GithubAttributeRewriter {
  constructor(attributeName, baseUrl, proxyOrigin) {
    this.attributeName = attributeName;
    this.baseUrl = baseUrl;
    this.proxyOrigin = proxyOrigin;
  }

  element(element) {
    const value = element.getAttribute(this.attributeName);
    const rewritten = proxifyGithubUrl(value, this.baseUrl, this.proxyOrigin);
    if (rewritten && rewritten !== value) {
      element.setAttribute(this.attributeName, rewritten);
    }
  }
}

class GithubSrcsetRewriter {
  constructor(baseUrl, proxyOrigin) {
    this.baseUrl = baseUrl;
    this.proxyOrigin = proxyOrigin;
  }

  element(element) {
    const value = element.getAttribute("srcset");
    const rewritten = rewriteSrcset(value, this.baseUrl, this.proxyOrigin);
    if (rewritten && rewritten !== value) {
      element.setAttribute("srcset", rewritten);
    }
  }
}

class GithubMetaRefreshRewriter {
  constructor(baseUrl, proxyOrigin) {
    this.baseUrl = baseUrl;
    this.proxyOrigin = proxyOrigin;
  }

  element(element) {
    const value = element.getAttribute("content");
    if (!value || !/url\s*=/i.test(value)) {
      return;
    }

    const rewritten = value.replace(/(url\s*=\s*)([^;]+)/i, (_match, prefix, rawUrl) => {
      const trimmed = rawUrl.trim().replace(/^['"]|['"]$/g, "");
      return `${prefix}${proxifyGithubUrl(trimmed, this.baseUrl, this.proxyOrigin) || trimmed}`;
    });

    element.setAttribute("content", rewritten);
  }
}

class GithubStyleAttributeRewriter {
  constructor(baseUrl, proxyOrigin) {
    this.baseUrl = baseUrl;
    this.proxyOrigin = proxyOrigin;
  }

  element(element) {
    const value = element.getAttribute("style");
    const rewritten = rewriteCssUrls(value, this.baseUrl, this.proxyOrigin);
    if (rewritten && rewritten !== value) {
      element.setAttribute("style", rewritten);
    }
  }
}

async function rewriteTextBody(response, headers, rewriter) {
  const text = await response.text();
  return new Response(rewriter(text), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function rewriteCssUrls(css, baseUrl, proxyOrigin) {
  if (!css) {
    return css;
  }

  return css
    .replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (match, quote, rawUrl) => {
      const rewritten = proxifyGithubUrl(rawUrl.trim(), baseUrl, proxyOrigin);
      return rewritten ? `url(${quote}${rewritten}${quote})` : match;
    })
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (match, quote, rawUrl) => {
      const rewritten = proxifyGithubUrl(rawUrl.trim(), baseUrl, proxyOrigin);
      return rewritten ? `@import ${quote}${rewritten}${quote}` : match;
    });
}

function rewriteSrcset(value, baseUrl, proxyOrigin) {
  if (!value) {
    return value;
  }

  return value.split(",")
    .map((candidate) => {
      const trimmed = candidate.trim();
      if (!trimmed) {
        return candidate;
      }

      const firstSpace = trimmed.search(/\s/);
      const rawUrl = firstSpace === -1 ? trimmed : trimmed.slice(0, firstSpace);
      const descriptor = firstSpace === -1 ? "" : trimmed.slice(firstSpace);
      return `${proxifyGithubUrl(rawUrl, baseUrl, proxyOrigin) || rawUrl}${descriptor}`;
    })
    .join(", ");
}

function proxifyGithubUrl(rawValue, baseUrl, proxyOrigin) {
  if (!rawValue) {
    return rawValue;
  }

  const value = String(rawValue).trim();
  if (
    !value
    || value.startsWith("#")
    || /^(?:mailto|tel|javascript|data|blob):/i.test(value)
  ) {
    return rawValue;
  }

  let targetUrl;
  try {
    targetUrl = new URL(value, baseUrl);
  } catch {
    return rawValue;
  }

  if (!["http:", "https:"].includes(targetUrl.protocol) || !isGithubProxyHost(targetUrl.hostname)) {
    return rawValue;
  }

  targetUrl.username = "";
  targetUrl.password = "";

  if (targetUrl.hostname === "github.com" || targetUrl.hostname === "www.github.com") {
    return `${proxyOrigin}/gh${targetUrl.pathname}${targetUrl.search}${targetUrl.hash}`;
  }

  return `${proxyOrigin}/${targetUrl.hostname}${targetUrl.pathname}${targetUrl.search}${targetUrl.hash}`;
}

function isPrivateHostname(hostname) {
  if (!hostname || hostname.endsWith(".local") || hostname.endsWith(".localhost")) {
    return true;
  }

  if (hostname.includes(":")) {
    const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return normalized === "::1"
      || normalized === "0:0:0:0:0:0:0:1"
      || normalized.startsWith("fc")
      || normalized.startsWith("fd")
      || normalized.startsWith("fe80:");
  }

  const parts = hostname.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part))) {
    return false;
  }

  const nums = parts.map(Number);
  if (nums.some((num) => num < 0 || num > 255)) {
    return true;
  }

  const [a, b] = nums;
  return a === 0
    || a === 10
    || a === 127
    || a === 169 && b === 254
    || a === 172 && b >= 16 && b <= 31
    || a === 192 && b === 168
    || a >= 224;
}

function parseHostList(value) {
  return String(value || "")
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
}

function isRedirect(status) {
  return [301, 302, 303, 307, 308].includes(status);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET, HEAD, OPTIONS");
  headers.set("access-control-allow-headers", "range, if-none-match, if-modified-since, accept, user-agent, authorization, x-proxy-password");
  headers.set("access-control-expose-headers", "content-length, content-range, content-type, content-disposition, accept-ranges, etag, last-modified, x-proxy-final-host");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function json(data, status = 200, extraHeaders = {}) {
  return withCors(
    new Response(JSON.stringify(data, null, 2), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        ...extraHeaders,
      },
    }),
  );
}

function renderGithubPortal(proxyOrigin, initialSearchQuery = "") {
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GitHub 代理入口</title>
  ${themeHeadScript()}
  <style>
    ${themeCss()}
    :root { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); }
    main { width: min(760px, calc(100vw - 32px)); display: grid; gap: 16px; }
    section { display: grid; gap: 12px; padding: 24px; border: 1px solid var(--border); border-radius: 16px; background: var(--panel); box-shadow: var(--shadow); }
    h1, h2 { margin: 0; }
    h1 { font-size: 28px; }
    h2 { font-size: 18px; }
    p { margin: 0; color: var(--muted); line-height: 1.7; }
    form { display: grid; gap: 10px; }
    input, button { min-height: 44px; border-radius: 8px; font: inherit; }
    input { border: 1px solid var(--border); padding: 0 12px; background: var(--panel-2); color: var(--text); }
    button { border: 0; background: var(--button); color: var(--button-text); cursor: pointer; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
    .quick { display: flex; flex-wrap: wrap; gap: 8px; }
    .quick a { padding: 7px 10px; border-radius: 999px; color: var(--link); background: var(--panel-2); text-decoration: none; border: 1px solid var(--border); }
    .trending-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .trending-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
    .trend-card { display: grid; gap: 8px; padding: 14px; border: 1px solid var(--border); border-radius: 12px; background: var(--panel-2); color: inherit; text-decoration: none; }
    .trend-card:hover { border-color: var(--link); }
    .trend-name { color: var(--link); font-weight: 700; overflow-wrap: anywhere; }
    .trend-desc { min-height: 42px; }
    .trend-meta { display: flex; flex-wrap: wrap; gap: 10px; color: var(--muted); font-size: 13px; }
    .muted { color: var(--muted); }
    code { padding: 2px 5px; border-radius: 5px; background: var(--panel-2); }
  </style>
</head>
<body>
  ${themeToggleHtml()}
  <main>
    <section>
      <h1>GitHub 代理入口</h1>
      <p>为了避免 GitHub 首页脚本在代理环境下闪烁、搜索框失效，这里用一个轻量入口替代原首页。只建议浏览公开页面和下载公开文件，不要登录。</p>
    </section>
    <div class="grid">
      <section>
        <h2>打开用户或仓库</h2>
        <form id="repo-form">
          <input id="repo-path" placeholder="torvalds/linux 或 microsoft/vscode" autocomplete="off" autofocus required>
          <button type="submit">打开</button>
        </form>
        <p>也可以直接访问 <code>/gh/user/repo</code>。</p>
      </section>
      <section>
        <h2>搜索公开内容</h2>
        <form id="search-form">
          <input id="search-query" placeholder="搜索仓库、代码或用户" autocomplete="off" value="${escapeHtml(initialSearchQuery)}" required>
          <button type="submit">搜索 GitHub</button>
        </form>
        <p>搜索会跳到 <code>/gh/search?q=...</code>，不走 GitHub 首页的 JS 搜索框。</p>
      </section>
    </div>
    <section>
      <h2>快捷入口</h2>
      <div class="quick">
        <a href="${proxyOrigin}/gh/trending">Trending</a>
        <a href="${proxyOrigin}/gh/topics">Topics</a>
        <a href="${proxyOrigin}/gh/explore">Explore</a>
        <a href="${proxyOrigin}/gh/microsoft/vscode">VS Code</a>
        <a href="${proxyOrigin}/gh/torvalds/linux">Linux</a>
      </div>
    </section>
    <section id="search-results-section" hidden>
      <div class="trending-header">
        <h2>Search Results</h2>
        <span id="search-results-query" class="muted"></span>
      </div>
      <div id="search-results-list" class="trending-list"></div>
      <p id="search-results-status" class="muted"></p>
    </section>
    <section>
      <div class="trending-header">
        <h2>Daily Trending</h2>
        <span id="trending-date" class="muted">loading...</span>
      </div>
      <div id="trending-list" class="trending-list"></div>
      <p id="trending-status" class="muted">Fetching GitHub Trending once per day and caching it in the Worker.</p>
    </section>
  </main>
  <script>
    const proxyOrigin = "${proxyOrigin}";
    const initialSearchQuery = ${scriptJson(initialSearchQuery)};
    const normalizeGithubPath = (value) => value
      .trim()
      .replace(/^https?:\\/\\/(www\\.)?github\\.com\\/?/i, "")
      .replace(/^\\/+/, "");

    document.getElementById("repo-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const path = normalizeGithubPath(document.getElementById("repo-path").value);
      if (path) location.href = proxyOrigin + "/gh/" + path;
    });

    document.getElementById("search-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const query = document.getElementById("search-query").value.trim();
      if (query) {
        history.replaceState(null, "", proxyOrigin + "/gh/search?q=" + encodeURIComponent(query));
        runSearch(query);
      }
    });

    const createText = (tagName, className, text) => {
      const element = document.createElement(tagName);
      if (className) element.className = className;
      element.textContent = text || "";
      return element;
    };

    const renderProjectCards = (projects, list) => {
      list.textContent = "";
      for (const project of projects || []) {
        const card = document.createElement("a");
        card.className = "trend-card";
        card.href = project.url;
        card.appendChild(createText("div", "trend-name", project.name));
        card.appendChild(createText("p", "trend-desc muted", project.description || "No description."));

        const meta = document.createElement("div");
        meta.className = "trend-meta";
        for (const value of [project.language, project.stars && "★ " + project.stars, project.todayStars, project.updatedAt && "Updated " + project.updatedAt]) {
          if (value) meta.appendChild(createText("span", "", value));
        }
        card.appendChild(meta);
        list.appendChild(card);
      }
    };

    const runSearch = (query) => {
      const section = document.getElementById("search-results-section");
      const list = document.getElementById("search-results-list");
      const status = document.getElementById("search-results-status");
      section.hidden = false;
      document.getElementById("search-results-query").textContent = query;
      list.textContent = "";
      status.textContent = "Searching cached GitHub API...";

      return fetch(proxyOrigin + "/__github_search?q=" + encodeURIComponent(query), { credentials: "same-origin" })
        .then((response) => response.json().then((data) => ({ ok: response.ok, data })))
        .then(({ ok, data }) => {
          if (!ok || data.error) {
            status.textContent = data.error || "GitHub search is temporarily unavailable.";
            return;
          }

          renderProjectCards(data.projects, list);
          status.textContent = data.projects && data.projects.length
            ? "Results are cached for a few hours to avoid GitHub rate limits."
            : "No repositories found.";
        })
        .catch(() => {
          status.textContent = "Search is temporarily unavailable. Try a direct /gh/user/repo link.";
        });
    };

    if (initialSearchQuery) {
      runSearch(initialSearchQuery);
    }

    const renderTrending = (data) => {
      const list = document.getElementById("trending-list");
      const status = document.getElementById("trending-status");
      document.getElementById("trending-date").textContent = data.date || "today";
      list.textContent = "";

      if (!data.projects || data.projects.length === 0) {
        status.textContent = "No trending projects found today.";
        return;
      }

      renderProjectCards(data.projects, list);

      status.textContent = "Updated daily from GitHub Trending.";
    };

    const trendingDate = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(new Date());

    fetch(proxyOrigin + "/__github_trending?date=" + encodeURIComponent(trendingDate), {
      credentials: "same-origin",
      cache: "no-store",
    })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("Trending unavailable")))
      .then(renderTrending)
      .catch(() => {
        document.getElementById("trending-date").textContent = "unavailable";
        document.getElementById("trending-status").textContent = "Trending is temporarily unavailable. Quick links still work.";
      });
  </script>
  ${themeToggleScript()}
</body>
</html>`;

  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

function renderGithubRepoPage(proxyOrigin, owner, repo, contentPath = "") {
  const repoFullName = `${owner}/${repo}`;
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(repoFullName)} - GitHub Lite</title>
  ${themeHeadScript()}
  <style>
    ${themeCss()}
    :root { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--text); }
    main { width: min(1080px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0; display: grid; gap: 16px; }
    section, header { display: grid; gap: 12px; padding: 22px; border: 1px solid var(--border); border-radius: 16px; background: var(--panel); }
    h1, h2, h3, p { margin: 0; }
    a { color: var(--link); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .muted { color: var(--muted); }
    .meta, .tabs, .assets { display: flex; flex-wrap: wrap; gap: 10px; }
    .pill, button { border: 1px solid var(--border); border-radius: 999px; padding: 7px 10px; background: var(--panel-2); color: var(--text); }
    button { cursor: pointer; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
    .file-list, .release-list { display: grid; gap: 8px; }
    .row, .release { display: grid; gap: 6px; padding: 12px; border: 1px solid var(--border); border-radius: 12px; background: var(--panel-2); }
    pre { margin: 0; overflow: auto; white-space: pre-wrap; word-break: break-word; max-height: 680px; padding: 16px; border-radius: 12px; background: var(--panel-2); border: 1px solid var(--border); line-height: 1.55; }
    code { padding: 2px 5px; border-radius: 5px; background: var(--panel-2); }
    .markdown { display: block; overflow-wrap: anywhere; line-height: 1.65; }
    .markdown h1, .markdown h2, .markdown h3 { margin: 1.2em 0 .5em; }
    .markdown p, .markdown ul, .markdown ol, .markdown blockquote, .markdown pre { margin: .75em 0; }
    .markdown img { max-width: 100%; border-radius: 8px; }
    .markdown blockquote { padding-left: 12px; border-left: 4px solid var(--border); color: var(--muted); }
    .markdown table { display: block; max-width: 100%; overflow: auto; border-collapse: collapse; }
    .markdown th, .markdown td { border: 1px solid var(--border); padding: 6px 8px; }
    .copy-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .copy-row code { overflow-wrap: anywhere; }
    .notice { display: none; padding: 10px 12px; border: 1px solid #d29922; border-radius: 10px; background: rgba(210,153,34,.12); color: var(--text); }
    .notice.show { display: block; }
  </style>
</head>
<body>
  ${themeToggleHtml()}
  <main>
    <header>
      <p><a href="${proxyOrigin}/gh">← GitHub Lite</a></p>
      <h1 id="repo-name">${escapeHtml(repoFullName)}</h1>
      <p id="repo-description" class="muted">Loading repository summary...</p>
      <p id="repo-warning" class="notice"></p>
      <div id="repo-meta" class="meta"></div>
      <div class="tabs">
        <a class="pill" href="#code">Code</a>
        <a class="pill" href="#readme">README</a>
        <a class="pill" href="#releases">Releases</a>
      </div>
      <div class="copy-row">
        <span class="muted">Raw prefix:</span>
        <code id="raw-base-text">${proxyOrigin}/raw/${escapeHtml(repoFullName)}/main/</code>
        <button id="copy-raw-base" type="button">Copy</button>
      </div>
    </header>
    <section id="code">
      <h2>Code</h2>
      <p class="muted">Top-level files. File links use <code>/raw/owner/repo/branch/path</code>, friendly for curl/NAS scripts.</p>
      <p id="code-source" class="muted"></p>
      <div class="meta">
        <span id="current-path" class="pill"></span>
        <a class="pill" href="${proxyOrigin}/gh/${escapeHtml(repoFullName)}">Root</a>
      </div>
      <div id="file-list" class="file-list"></div>
    </section>
    <section id="readme">
      <h2>README</h2>
      <p id="readme-source" class="muted"></p>
      <article id="readme-content" class="markdown muted">Loading README...</article>
    </section>
    <section id="releases">
      <h2>Releases</h2>
      <p id="releases-source" class="muted"></p>
      <div id="release-list" class="release-list"></div>
    </section>
  </main>
  <script>
    const proxyOrigin = ${scriptJson(proxyOrigin)};
    const owner = ${scriptJson(owner)};
    const repo = ${scriptJson(repo)};
    const contentPath = ${scriptJson(normalizeGithubContentPath(contentPath))};

    const createText = (tagName, className, text) => {
      const element = document.createElement(tagName);
      if (className) element.className = className;
      element.textContent = text || "";
      return element;
    };

    const createLink = (href, text, className) => {
      const element = document.createElement("a");
      element.href = href;
      element.textContent = text || href;
      if (className) element.className = className;
      return element;
    };

    const escapeHtmlClient = (value) => String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

    const sanitizeMarkdown = (value) => String(value || "")
      .replace(/<br\\s*\\/?\\s*>/gi, "\\n")
      .replace(/<\\/?(?:div|p|tbody|thead|tr|table)[^>]*>/gi, "\\n")
      .replace(/<\\/?(?:td|th)[^>]*>/gi, " ")
      .replace(/<a\\s+[^>]*href=["']([^"']+)["'][^>]*>([\\s\\S]*?)<\\/a>/gi, "[$2]($1)")
      .replace(/<img\\s+[^>]*src=["']([^"']+)["'][^>]*alt=["']([^"']*)["'][^>]*>/gi, "![$2]($1)")
      .replace(/<img\\s+[^>]*alt=["']([^"']*)["'][^>]*src=["']([^"']+)["'][^>]*>/gi, "![$1]($2)")
      .replace(/<img\\s+[^>]*src=["']([^"']+)["'][^>]*>/gi, "![]($1)")
      .replace(/<[^>]+>/g, "");

    const renderInlineMarkdown = (value) => escapeHtmlClient(value)
      .replace(/!\\[([^\\]]*)\\]\\(([^\\s)]+)(?:\\s+"[^"]*")?\\)/g, (_match, alt, href) => '<img alt="' + alt + '" src="' + resolveReadmeUrl(href) + '">')
      .replace(/\\[([^\\]]+)\\]\\(([^\\s)]+)(?:\\s+"[^"]*")?\\)/g, (_match, text, href) => '<a href="' + resolveReadmeUrl(href) + '" rel="noreferrer">' + text + '</a>')
      .replace(new RegExp(String.fromCharCode(96) + "([^" + String.fromCharCode(96) + "]+)" + String.fromCharCode(96), "g"), '<code>$1</code>')
      .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>')
      .replace(/\\*([^*]+)\\*/g, '<em>$1</em>');

    const resolveReadmeUrl = (href) => {
      if (!href || href.startsWith("#")) return href || "";
      if (/^(mailto:|tel:)/i.test(href)) return href;

      try {
        const url = new URL(href);
        if (url.hostname === "github.com" || url.hostname === "www.github.com") {
          const rawPath = url.pathname.replace(/^\\/+/, "");
          const blobMatch = rawPath.match(/^([^/]+)\\/([^/]+)\\/blob\\/([^/]+)\\/(.+)$/);
          const rawMatch = rawPath.match(/^([^/]+)\\/([^/]+)\\/raw\\/([^/]+)\\/(.+)$/);
          if (blobMatch || rawMatch) {
            const match = blobMatch || rawMatch;
            return proxyOrigin + "/raw/" + match[1] + "/" + match[2] + "/" + match[3] + "/" + match[4] + url.search + url.hash;
          }
          return proxyOrigin + "/gh/" + rawPath + url.search + url.hash;
        }

        if (url.hostname === "raw.githubusercontent.com") {
          return proxyOrigin + "/raw/" + url.pathname.replace(/^\\/+/, "") + url.search + url.hash;
        }

        if (url.hostname.endsWith(".githubusercontent.com") || url.hostname.endsWith(".githubassets.com")) {
          return proxyOrigin + "/" + url.hostname + url.pathname + url.search + url.hash;
        }

        if (/^https?:/i.test(href)) return href;
      } catch {
      }

      const rawBase = document.getElementById("raw-base-text").textContent;
      return rawBase + href.replace(/^\\.\\//, "").replace(/^\\//, "");
    };

    const renderMarkdown = (markdown) => {
      const lines = sanitizeMarkdown(markdown).replace(/\\r\\n/g, "\\n").split("\\n");
      const html = [];
      let paragraph = [];
      let listOpen = false;
      let codeOpen = false;
      let code = [];

      const flushParagraph = () => {
        if (paragraph.length) {
          html.push("<p>" + renderInlineMarkdown(paragraph.join(" ")) + "</p>");
          paragraph = [];
        }
      };
      const closeList = () => {
        if (listOpen) {
          html.push("</ul>");
          listOpen = false;
        }
      };

      for (const line of lines) {
        if (line.trim().startsWith(String.fromCharCode(96, 96, 96))) {
          if (codeOpen) {
            html.push("<pre><code>" + escapeHtmlClient(code.join("\\n")) + "</code></pre>");
            code = [];
            codeOpen = false;
          } else {
            flushParagraph();
            closeList();
            codeOpen = true;
          }
          continue;
        }

        if (codeOpen) {
          code.push(line);
          continue;
        }

        const heading = line.match(/^(#{1,3})\\s+(.+)$/);
        if (heading) {
          flushParagraph();
          closeList();
          html.push("<h" + heading[1].length + ">" + renderInlineMarkdown(heading[2]) + "</h" + heading[1].length + ">");
          continue;
        }

        const item = line.match(/^\\s*[-*+]\\s+(.+)$/);
        if (item) {
          flushParagraph();
          if (!listOpen) {
            html.push("<ul>");
            listOpen = true;
          }
          html.push("<li>" + renderInlineMarkdown(item[1]) + "</li>");
          continue;
        }

        if (/^>\\s?/.test(line)) {
          flushParagraph();
          closeList();
          html.push("<blockquote>" + renderInlineMarkdown(line.replace(/^>\\s?/, "")) + "</blockquote>");
          continue;
        }

        if (!line.trim()) {
          flushParagraph();
          closeList();
          continue;
        }

        paragraph.push(line.trim());
      }

      if (codeOpen) html.push("<pre><code>" + escapeHtmlClient(code.join("\\n")) + "</code></pre>");
      flushParagraph();
      closeList();
      return html.join("\\n") || "<p>No README found.</p>";
    };

    document.getElementById("copy-raw-base").addEventListener("click", () => {
      const value = document.getElementById("raw-base-text").textContent;
      navigator.clipboard?.writeText(value);
    });

    const renderRepo = (data) => {
      const repoInfo = data.repo || {};
      document.getElementById("repo-name").textContent = repoInfo.fullName || owner + "/" + repo;
      document.getElementById("repo-description").textContent = repoInfo.description || "No description.";
      const warning = document.getElementById("repo-warning");
      if (data.warning) {
        warning.textContent = data.warning + " 当前页面已使用备用数据源，下面内容可正常使用。";
        warning.classList.add("show");
      } else {
        warning.textContent = "";
        warning.classList.remove("show");
      }
      document.getElementById("raw-base-text").textContent = (repoInfo.rawBaseUrl || proxyOrigin + "/raw/" + owner + "/" + repo + "/main") + "/";
      document.getElementById("current-path").textContent = data.path ? "/" + data.path : "/";
      const sources = data.sources || {};
      document.getElementById("code-source").textContent = sources.contents ? "Source: " + sources.contents : "";
      document.getElementById("readme-source").textContent = sources.readme ? "Source: " + sources.readme : "";
      document.getElementById("releases-source").textContent = sources.releases ? "Source: " + sources.releases : "";

      const meta = document.getElementById("repo-meta");
      meta.textContent = "";
      for (const value of [repoInfo.language, repoInfo.stars && "★ " + repoInfo.stars, repoInfo.forks && "Forks " + repoInfo.forks, repoInfo.license, repoInfo.updatedAt && "Updated " + repoInfo.updatedAt]) {
        if (value) meta.appendChild(createText("span", "pill", value));
      }

      const files = document.getElementById("file-list");
      files.textContent = "";
      for (const item of data.contents || []) {
        const row = document.createElement("div");
        row.className = "row";
        row.appendChild(createLink(item.url, (item.type === "dir" ? "📁 " : "📄 ") + item.name));
        if (item.size) row.appendChild(createText("span", "muted", item.size));
        files.appendChild(row);
      }
      if (!files.childNodes.length) files.textContent = "No code listing available. README, Releases and Raw links may still work.";

      document.getElementById("readme-content").classList.remove("muted");
      document.getElementById("readme-content").innerHTML = renderMarkdown(data.readme || "No README found.");

      const releases = document.getElementById("release-list");
      releases.textContent = "";
      for (const release of data.releases || []) {
        const card = document.createElement("div");
        card.className = "release";
        card.appendChild(createText("h3", "", release.name || release.tag));
        card.appendChild(createText("p", "muted", [release.tag, release.publishedAt].filter(Boolean).join(" · ")));
        if (release.body) {
          const body = document.createElement("div");
          body.className = "markdown";
          body.innerHTML = renderMarkdown(release.body);
          card.appendChild(body);
        }
        const assets = document.createElement("div");
        assets.className = "assets";
        for (const asset of release.assets || []) {
          assets.appendChild(createLink(asset.url, asset.size ? asset.name + " (" + asset.size + ")" : asset.name, "pill"));
        }
        if (assets.childNodes.length) card.appendChild(assets);
        releases.appendChild(card);
      }
      if (!releases.childNodes.length) releases.textContent = "No releases found.";
    };

    const summaryUrl = new URL(proxyOrigin + "/__github_repo");
    summaryUrl.searchParams.set("owner", owner);
    summaryUrl.searchParams.set("repo", repo);
    if (contentPath) summaryUrl.searchParams.set("path", contentPath);

    fetch(summaryUrl.toString(), { credentials: "same-origin" })
      .then((response) => response.json().then((data) => ({ ok: response.ok, data })))
      .then(({ ok, data }) => {
        if (!ok || data.error) throw new Error(data.error || "Failed to load repository.");
        renderRepo(data);
      })
      .catch((error) => {
        document.getElementById("repo-description").textContent = error.message || "Failed to load repository.";
        document.getElementById("readme-content").textContent = "Repository summary is temporarily unavailable.";
      });
  </script>
  ${themeToggleScript()}
</body>
</html>`;

  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

function renderUnlockPage(requestUrl) {
  const hiddenInputs = [...requestUrl.searchParams]
    .filter(([name]) => name !== "token")
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join("");
  const action = requestUrl.pathname || "/";
  const exampleUrl = `${requestUrl.origin}/gh/user`;
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>解锁代理访问</title>
  ${themeHeadScript()}
  <style>
    ${themeCss()}
    :root { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); }
    main { width: min(560px, calc(100vw - 32px)); padding: 28px; border: 1px solid var(--border); border-radius: 14px; background: var(--panel); box-shadow: var(--shadow); }
    h1 { margin: 0 0 10px; font-size: 24px; }
    p { margin: 8px 0 16px; color: var(--muted); line-height: 1.7; }
    form { display: grid; gap: 12px; }
    input, button { min-height: 42px; border-radius: 8px; font: inherit; }
    input { border: 1px solid var(--border); padding: 0 12px; background: var(--panel-2); color: var(--text); }
    button { border: 0; background: var(--button); color: var(--button-text); cursor: pointer; }
    code { padding: 2px 5px; border-radius: 5px; background: var(--panel-2); }
  </style>
</head>
<body>
  ${themeToggleHtml()}
  <main>
    <h1>输入一次代理密码</h1>
    <p>解锁后会保存一个仅当前代理域名可用的临时会话，之后可以直接打开类似 <code>${escapeHtml(exampleUrl)}</code> 的短链接。</p>
    <form method="get" action="${escapeHtml(action)}">
      ${hiddenInputs}
      <input name="token" type="password" placeholder="代理密码" autocomplete="current-password" autofocus required>
      <button type="submit">继续访问</button>
    </form>
  </main>
  ${themeToggleScript()}
</body>
</html>`;

  return new Response(html, {
    status: 401,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

function renderGithubLoginWarning(proxyOrigin, targetUrl) {
  const officialUrl = `https://${targetUrl.hostname}${targetUrl.pathname}${targetUrl.search}`;
  const homeUrl = `${proxyOrigin}/github.com/`;
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GitHub 代理登录保护</title>
  ${themeHeadScript()}
  <style>
    ${themeCss()}
    :root { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); }
    main { width: min(720px, calc(100vw - 32px)); padding: 28px; border: 1px solid var(--border); border-radius: 12px; background: var(--panel); box-shadow: var(--shadow); }
    h1 { margin: 0 0 12px; font-size: 24px; }
    p { margin: 10px 0; line-height: 1.7; color: var(--muted); }
    a { color: var(--link); }
    .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 20px; }
    .button { display: inline-flex; align-items: center; min-height: 40px; padding: 0 14px; border-radius: 6px; text-decoration: none; background: var(--button); color: var(--button-text); }
    .ghost { background: var(--panel-2); color: var(--text); border: 1px solid var(--border); }
    code { padding: 2px 5px; border-radius: 5px; background: var(--panel-2); }
  </style>
</head>
<body>
  ${themeToggleHtml()}
  <main>
    <h1>已拦截 GitHub 登录页面</h1>
    <p>这个代理只适合浏览公开页面、查看仓库和下载公开文件。为了避免密码、Token、2FA 验证码或 GitHub Cookie 经过代理域名，这里不会代理 GitHub 登录相关页面。</p>
    <p>如果你确实需要登录，请直接访问 GitHub 官方域名：<code>${escapeHtml(officialUrl)}</code></p>
    <div class="actions">
      <a class="button" href="${escapeHtml(officialUrl)}" rel="noreferrer">打开 GitHub 官方页面</a>
      <a class="button ghost" href="${escapeHtml(homeUrl)}">回到代理首页</a>
    </div>
  </main>
  ${themeToggleScript()}
</body>
</html>`;

  return new Response(html, {
    status: 403,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function scriptJson(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function themeHeadScript() {
  return `<script>
    (() => {
      const stored = localStorage.getItem("udp-theme");
      const theme = stored || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      document.documentElement.dataset.theme = theme;
    })();
  </script>`;
}

function themeToggleHtml() {
  return `<button id="theme-toggle" class="theme-toggle" type="button" aria-label="Toggle theme">Theme</button>`;
}

function themeToggleScript() {
  return `<script>
    (() => {
      const button = document.getElementById("theme-toggle");
      if (!button) return;
      const update = () => {
        const theme = document.documentElement.dataset.theme || "light";
        button.textContent = theme === "dark" ? "Light" : "Dark";
        button.title = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
      };
      button.addEventListener("click", () => {
        const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        document.documentElement.dataset.theme = next;
        localStorage.setItem("udp-theme", next);
        update();
      });
      update();
    })();
  </script>`;
}

function themeCss() {
  return `
    :root {
      color-scheme: light;
      --bg:#f6f8fa;
      --panel:#fff;
      --panel-2:#f6f8fa;
      --border:#d0d7de;
      --text:#24292f;
      --muted:#57606a;
      --link:#0969da;
      --button:#0969da;
      --button-text:#fff;
      --shadow:0 12px 36px rgba(27,31,36,.08);
    }
    :root[data-theme="dark"] {
      color-scheme: dark;
      --bg:#0d1117;
      --panel:#161b22;
      --panel-2:#0d1117;
      --border:#30363d;
      --text:#f0f6fc;
      --muted:#8b949e;
      --link:#58a6ff;
      --button:#238636;
      --button-text:#fff;
      --shadow:0 18px 50px rgba(0,0,0,.28);
    }
    .theme-toggle {
      position: fixed;
      right: 16px;
      bottom: 16px;
      z-index: 2147483647;
      min-width: 64px;
      height: 44px;
      padding: 0 12px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--text);
      box-shadow: var(--shadow);
      cursor: pointer;
      font-size: 18px;
    }
  `;
}

function renderHomePage(proxyUrl) {
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Universal Download Proxy</title>
  ${themeHeadScript()}
  <style>
    ${themeCss()}
    :root { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); }
    main { width: min(860px, calc(100vw - 32px)); display: grid; gap: 16px; }
    section { display: grid; gap: 12px; padding: 24px; border: 1px solid var(--border); border-radius: 14px; background: var(--panel); box-shadow: var(--shadow); }
    form { display: grid; gap: 12px; }
    h1 { margin: 0; font-size: 26px; }
    h2 { margin: 0; font-size: 18px; }
    input, textarea, button { min-height: 42px; border-radius: 6px; font: inherit; }
    input, textarea { border: 1px solid var(--border); padding: 0 12px; background: var(--panel-2); color: var(--text); }
    textarea { min-height: 108px; padding: 10px 12px; resize: vertical; line-height: 1.55; }
    button { border: 0; background: var(--button); color: var(--button-text); cursor: pointer; }
    p { margin: 0; color: var(--muted); line-height: 1.7; }
    code { padding: 2px 5px; border-radius: 5px; background: var(--panel-2); }
    pre { margin: 0; min-height: 56px; padding: 12px; overflow: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid var(--border); border-radius: 8px; background: var(--panel-2); color: var(--text); }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; }
    .actions button { padding: 0 14px; }
  </style>
</head>
<body>
  ${themeToggleHtml()}
  <main>
    <section>
      <h1>Universal Download Proxy</h1>
      <p>GitHub 代理最简单：输入 <code>user</code> 或 <code>user/repo</code>，也可以直接访问 <code>/gh/user</code>。</p>
      <input id="token" type="password" placeholder="代理密码（可选；未解锁时会自动提示）">
    </section>
    <section>
      <h2>GitHub 公开页面</h2>
      <form id="github-form" action="javascript:void 0">
        <input id="github-path" type="text" placeholder="user 或 user/repo" required>
        <button id="open-github" type="button">打开 GitHub 代理</button>
      </form>
      <p>只建议浏览公开仓库和下载公开文件；不要在代理里登录 GitHub。</p>
    </section>
    <section>
      <h2>普通文件下载</h2>
      <form id="proxy-form" action="javascript:void 0">
        <input id="url" name="url" type="url" placeholder="https://example.com/file.zip" required>
        <button id="open-proxy" type="button">开始代理下载</button>
      </form>
    </section>
    <section>
      <h2>安装命令加速</h2>
      <textarea id="install-command" spellcheck="false" placeholder="curl -fsSL https://get.docker.com | sh"></textarea>
      <div class="actions">
        <button id="rewrite-command" type="button">生成加速命令</button>
        <button id="copy-command" type="button">复制结果</button>
      </div>
      <pre id="install-output">粘贴 curl / wget 安装命令后生成结果。</pre>
      <p>适合安装脚本、普通文件、GitHub Raw 和 Release 资产；不适合完整代理 <code>docker pull</code> 镜像。</p>
    </section>
  </main>
  <script>
    const proxyOrigin = "${proxyUrl.origin}";
    const getToken = () => document.getElementById("token").value;
    function trimUrlTail(value) {
      let url = value;
      let tail = "";
      while (url && "),.;]".includes(url.slice(-1))) {
        tail = url.slice(-1) + tail;
        url = url.slice(0, -1);
      }
      return { url, tail };
    }
    const addProxyToken = (value) => {
      const token = getToken();
      if (!token) return value;
      const target = new URL(value);
      target.searchParams.set("token", token);
      return target.toString();
    };
    function shellQuoteUrl(value) {
      const quote = String.fromCharCode(39);
      const doubleQuote = String.fromCharCode(34);
      const escapedQuote = quote + doubleQuote + quote + doubleQuote + quote;
      return quote + value.split(quote).join(escapedQuote) + quote;
    }
    const toProxyUrl = (rawUrl) => {
      let url;
      try {
        url = new URL(rawUrl);
      } catch {
        return rawUrl;
      }

      const host = url.hostname.toLowerCase();
      const path = url.pathname.replace(/^\\/+/, "");
      if (host === "raw.githubusercontent.com") {
        return addProxyToken(proxyOrigin + "/raw/" + path + url.search + url.hash);
      }

      if (host === "github.com" || host === "www.github.com") {
        const blobMatch = path.match(/^([^/]+)\\/([^/]+)\\/blob\\/([^/]+)\\/(.+)$/);
        const rawMatch = path.match(/^([^/]+)\\/([^/]+)\\/raw\\/([^/]+)\\/(.+)$/);
        if (blobMatch || rawMatch) {
          const match = blobMatch || rawMatch;
          return addProxyToken(proxyOrigin + "/raw/" + match[1] + "/" + match[2] + "/" + match[3] + "/" + match[4] + url.search + url.hash);
        }
        return addProxyToken(proxyOrigin + "/github.com/" + path + url.search + url.hash);
      }

      return addProxyToken(proxyOrigin + "/" + rawUrl);
    };
    function rewriteInstallCommand(command) {
      let replaced = false;
      const output = command.replace(/https?:\\/\\/[^\\s'"<>]+/gi, (match, offset, source) => {
        const parts = trimUrlTail(match);
        const proxied = toProxyUrl(parts.url);
        const previous = source[offset - 1] || "";
        const next = source[offset + match.length] || "";
        const quoted = previous === "'" || previous === '"' || next === "'" || next === '"';
        replaced = true;
        return (quoted ? proxied : shellQuoteUrl(proxied)) + parts.tail;
      });

      if (!replaced) {
        return "未发现 http/https 链接。";
      }

      return getToken()
        ? output
        : "# 提示：命令行使用建议先填代理密码，否则 curl/wget 可能拿到解锁页。\\n" + output;
    }

    function openGithubProxy() {
      let path = document.getElementById("github-path").value.trim();
      if (!path) {
        alert("先输入 GitHub 用户名或 user/repo");
        return;
      }
      path = path.replace(/^https?:\\/\\/(www\\.)?github\\.com\\/?/i, "").replace(/^\\/+/, "");
      const target = new URL(proxyOrigin + "/gh/" + path);
      const token = getToken();
      if (token) target.searchParams.set("token", token);
      location.href = target.toString();
    }

    function openProxyDownload() {
      const url = document.getElementById("url").value.trim();
      if (!url) {
        alert("先输入下载链接");
        return;
      }
      const token = getToken();
      const target = new URL(proxyOrigin + "/");
      target.searchParams.set("url", url);
      if (token) target.searchParams.set("token", token);
      location.href = target.toString();
    }

    document.getElementById("open-github").addEventListener("click", openGithubProxy);
    document.getElementById("open-proxy").addEventListener("click", openProxyDownload);
    document.getElementById("github-form").addEventListener("submit", (event) => {
      event.preventDefault();
      openGithubProxy();
    });
    document.getElementById("proxy-form").addEventListener("submit", (event) => {
      event.preventDefault();
      openProxyDownload();
    });

    document.getElementById("rewrite-command").addEventListener("click", () => {
      const command = document.getElementById("install-command").value.trim();
      document.getElementById("install-output").textContent = command
        ? rewriteInstallCommand(command)
        : "先粘贴一条 curl / wget 安装命令。";
    });

    document.getElementById("copy-command").addEventListener("click", () => {
      const value = document.getElementById("install-output").textContent;
      navigator.clipboard?.writeText(value);
    });
  </script>
  ${themeToggleScript()}
</body>
</html>`;

  return withCors(
    new Response(html, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      },
    }),
  );
}

function renderHome(proxyUrl) {
  const html = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Universal Download Proxy</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f7f9; color: #1b1f24; }
    main { width: min(680px, calc(100vw - 32px)); }
    form { display: grid; gap: 12px; padding: 24px; border: 1px solid #d8dee4; border-radius: 8px; background: #fff; }
    h1 { margin: 0 0 8px; font-size: 24px; }
    input, button { min-height: 42px; border-radius: 6px; font: inherit; }
    input { border: 1px solid #d8dee4; padding: 0 12px; }
    button { border: 0; background: #0969da; color: #fff; cursor: pointer; }
    p { margin: 0; color: #57606a; line-height: 1.6; }
    code { padding: 2px 4px; border-radius: 4px; background: #eef2f6; }
    @media (prefers-color-scheme: dark) {
      body { background: #0d1117; color: #f0f6fc; }
      form { background: #161b22; border-color: #30363d; }
      p { color: #8b949e; }
      input { background: #0d1117; border-color: #30363d; color: #f0f6fc; }
      code { background: #21262d; }
    }
  </style>
</head>
<body>
  <main>
    <form id="proxy-form">
      <h1>Universal Download Proxy</h1>
      <p>输入目标 URL 和密码后开始下载。密码也可以通过 <code>X-Proxy-Password</code> 或 <code>Authorization: Bearer</code> 传入。</p>
      <input id="url" name="url" type="url" placeholder="https://example.com/file.zip" required>
      <input id="token" name="token" type="password" placeholder="代理密码" required>
      <button type="submit">开始下载</button>
    </form>
  </main>
  <script>
    document.getElementById("proxy-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const url = document.getElementById("url").value.trim();
      const token = document.getElementById("token").value;
      const target = new URL("${proxyUrl.origin}/");
      target.searchParams.set("url", url);
      target.searchParams.set("token", token);
      location.href = target.toString();
    });
  </script>
</body>
</html>`;

  return withCors(
    new Response(html, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      },
    }),
  );
}
