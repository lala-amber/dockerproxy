/**
 * EdgeOne Pages Functions: Docker Hub reverse proxy for Docker Registry V2
 * - Works as Docker "registry-mirrors"
 * - Handles /v2/ ping (GET/HEAD)
 * - Provides local /v2/auth token proxy
 * - Adds "library/" prefix for single-segment repos
 * - (Optional) Follows DockerHub 307 redirects for blobs WITH Range passthrough
 *
 * Put this file at: functions/[[...path]].js
 */

const DOCKER_HUB = "https://registry-1.docker.io";

const CONTROL_TIMEOUT_MS = 15000;
const BLOB_TIMEOUT_MS = 180000;

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000;

function buildRoutes(hostname) {
  // Host allowlist mapping (current host -> Docker Hub).
  // If you want multiple hosts, expand this map carefully.
  return { [hostname]: DOCKER_HUB };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchWithTimeout(resource, options = {}, timeoutMs = CONTROL_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(resource, { ...options, signal: controller.signal });
    clearTimeout(id);
    return resp;
  } catch (e) {
    clearTimeout(id);
    if (e && e.name === "AbortError") throw new Error("Request timeout");
    throw e;
  }
}

async function fetchWithRetry(resource, options = {}) {
  const { retries = MAX_RETRIES, timeout = CONTROL_TIMEOUT_MS, ...fetchOptions } = options;

  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      const resp = await fetchWithTimeout(resource, fetchOptions, timeout);

      // Pass-through: ok / auth challenge / redirect to blob store
      if (resp.ok || resp.status === 401 || resp.status === 307) return resp;

      // Retry on 5xx
      if (resp.status >= 500 && i < retries - 1) {
        const delay = i === 0 ? 500 : RETRY_DELAY_MS * i;
        await sleep(delay);
        continue;
      }
      return resp;
    } catch (e) {
      lastErr = e;
      if (i < retries - 1) {
        const delay = i === 0 ? 500 : RETRY_DELAY_MS * i;
        await sleep(delay);
        continue;
      }
    }
  }
  throw lastErr || new Error("Max retries reached");
}

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function allowMethods() {
  return new Response(null, {
    status: 405,
    headers: { Allow: "GET, HEAD, OPTIONS" },
  });
}

// Docker daemon does not need CORS; leaving it harmless.
function addCors(resp) {
  const headers = new Headers(resp.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Range");
  return new Response(resp.body, { status: resp.status, headers });
}

function isSingleSegmentRepo(pathname) {
  const m = pathname.match(/^\/v2\/([^/]+)\/(manifests|tags|blobs)\b/i);
  return !!(m && !m[1].includes("/"));
}

function needsLibraryPrefix(pathname) {
  if (/^\/v2\/library\//i.test(pathname)) return false;
  return isSingleSegmentRepo(pathname);
}

function withLibraryPrefix(urlObj) {
  urlObj.pathname = urlObj.pathname.replace(/^\/v2\/([^/]+)\//i, "/v2/library/$1/");
  return urlObj;
}

function isBlobRequest(pathname) {
  return /^\/v2\/.+\/blobs\//i.test(pathname);
}

function parseAuthenticate(h) {
  const realm = h.match(/realm="([^"]+)"/i)?.[1];
  const service = h.match(/service="([^"]+)"/i)?.[1] || "";
  if (!realm) throw new Error("Missing realm in WWW-Authenticate");
  return { realm, service };
}

async function fetchToken({ realm, service }, scope, authorization) {
  const u = new URL(realm);
  if (service) u.searchParams.set("service", service);
  if (scope) u.searchParams.set("scope", scope);

  const headers = new Headers();
  if (authorization) headers.set("Authorization", authorization);

  return fetchWithRetry(u.toString(), { method: "GET", headers, redirect: "follow" });
}

// Return a local challenge so Docker daemon fetches token from our /v2/auth
function responseUnauthorized(hostname) {
  const headers = {
    "WWW-Authenticate": `Bearer realm="https://${hostname}/v2/auth",service="registry.docker.io"`,
  };
  return json({ message: "UNAUTHORIZED" }, 401, headers);
}

function filterRequestHeaders(requestHeaders) {
  const out = new Headers();
  for (const [k, v] of requestHeaders.entries()) {
    const lk = k.toLowerCase();
    // Strip hop-by-hop and platform-specific headers
    if (lk.startsWith("cf-")) continue;
    if (lk === "host") continue;
    if (lk === "connection") continue;
    if (lk === "keep-alive") continue;
    if (lk === "proxy-authenticate") continue;
    if (lk === "proxy-authorization") continue;
    if (lk === "te") continue;
    if (lk === "trailers") continue;
    if (lk === "transfer-encoding") continue;
    if (lk === "upgrade") continue;

    out.set(k, v);
  }
  return out;
}

/**
 * EdgeOne Pages Functions entry.
 * Ensure this file is catch-all so /v2/* never falls back to Pages 404.
 */
export async function onRequest(context) {
  const request = context.request;

  // Methods
  if (request.method === "OPTIONS") {
    return addCors(new Response(null, { status: 204 }));
  }
  if (!["GET", "HEAD"].includes(request.method)) {
    return addCors(allowMethods());
  }

  const url = new URL(request.url);

  try {
    return await handleRequest(request, url);
  } catch (e) {
    // EdgeOne Pages logs
    console.error("EdgeOne Pages function error:", e);
    return addCors(
      json({ error: "Bad Gateway", message: e?.message || "Unknown error" }, 502)
    );
  }
}

async function handleRequest(request, url) {
  // Root redirect (optional)
  if (url.pathname === "/") {
    return addCors(Response.redirect(`${url.protocol}//${url.host}/v2/`, 301));
  }

  const routes = buildRoutes(url.hostname);
  const upstream = routes[url.hostname];
  if (!upstream) {
    return addCors(json({ message: "Host not allowed", routes }, 404));
  }

  const isDockerHub = upstream === DOCKER_HUB;
  const authorization = request.headers.get("Authorization");

  // Normalize /v2 -> /v2/
  if (url.pathname === "/v2") {
    const u = new URL(url.toString());
    u.pathname = "/v2/";
    return addCors(Response.redirect(u.toString(), 301));
  }

  // /v2/ ping
  if (url.pathname === "/v2/") {
    const pingUrl = new URL(upstream + "/v2/");
    const headers = new Headers();
    if (authorization) headers.set("Authorization", authorization);

    const resp = await fetchWithRetry(pingUrl.toString(), {
      method: request.method, // forward HEAD/GET
      headers,
      redirect: "follow",
    });

    // Upstream requires auth -> challenge locally
    if (resp.status === 401) return addCors(responseUnauthorized(url.hostname));
    return addCors(resp);
  }

  // /v2/auth - local token proxy
  if (url.pathname === "/v2/auth") {
    const probe = await fetchWithRetry(new URL(upstream + "/v2/").toString(), {
      method: "GET",
      redirect: "follow",
    });

    if (probe.status !== 401) return addCors(probe);

    const authenticateStr = probe.headers.get("WWW-Authenticate");
    if (!authenticateStr) return addCors(probe);

    let wwwAuth;
    try {
      wwwAuth = parseAuthenticate(authenticateStr);
    } catch {
      return addCors(json({ message: "Bad WWW-Authenticate from upstream" }, 502));
    }

    // Scope rewrite for DockerHub single segment repo -> library/<name>
    let scope = url.searchParams.get("scope");
    if (scope && isDockerHub) {
      const parts = scope.split(":");
      if (parts.length === 3 && !parts[1].includes("/")) {
        parts[1] = "library/" + parts[1];
        scope = parts.join(":");
      }
    }

    const tokenResp = await fetchToken(wwwAuth, scope, authorization);
    return addCors(tokenResp);
  }

  // DockerHub library redirect for single-segment repos
  if (isDockerHub && needsLibraryPrefix(url.pathname)) {
    const redirectUrl = withLibraryPrefix(new URL(url.toString()));
    return addCors(Response.redirect(redirectUrl.toString(), 301));
  }

  // Forward to upstream
  const newUrl = new URL(upstream + url.pathname + (url.search || ""));
  const headers = filterRequestHeaders(request.headers);

  const newReq = new Request(newUrl.toString(), {
    method: request.method,
    headers,
    redirect: isDockerHub ? "manual" : "follow",
  });

  const timeout = isBlobRequest(url.pathname) ? BLOB_TIMEOUT_MS : CONTROL_TIMEOUT_MS;
  const resp = await fetchWithRetry(newReq, { timeout });

  // Convert upstream 401 -> local auth challenge
  if (resp.status === 401) {
    return addCors(responseUnauthorized(url.hostname));
  }

  // Handle DockerHub blob 307
  // IMPORTANT FIX: when following 307 internally, forward Range/Accept headers, and preserve HEAD vs GET.
  if (isDockerHub && resp.status === 307) {
    const loc = resp.headers.get("Location");
    if (!loc) return addCors(resp);

    let locationUrl;
    try {
      locationUrl = new URL(loc, upstream);
    } catch {
      return addCors(resp);
    }

    if (locationUrl.protocol !== "https:") {
      return addCors(resp);
    }

    // Forward only safe headers needed for blob fetch
    const h = new Headers();
    const range = request.headers.get("Range");
    if (range) h.set("Range", range);
    const accept = request.headers.get("Accept");
    if (accept) h.set("Accept", accept);
    const acceptEncoding = request.headers.get("Accept-Encoding");
    if (acceptEncoding) h.set("Accept-Encoding", acceptEncoding);

    // Keep method consistent (HEAD should remain HEAD)
    const redirected = await fetchWithRetry(locationUrl.toString(), {
      method: request.method,
      headers: h,
      redirect: "follow",
      timeout: BLOB_TIMEOUT_MS,
    });

    return addCors(redirected);
  }

  return addCors(resp);
}
