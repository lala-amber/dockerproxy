/**
 * EdgeOne Pages Functions: Docker Hub reverse proxy for Docker Registry V2
 * Goal: work reliably as Docker "registry-mirrors" on Pages environment.
 *
 * Key behaviors:
 *  - /v2/ ping supports GET/HEAD
 *  - /v2/auth proxies token from DockerHub auth realm
 *  - Adds library/ prefix for single-segment repos
 *  - IMPORTANT: For blobs, DO NOT download in Pages on 307. Just pass 307+Location to client.
 *    (Pages doing large blob streaming is prone to timeouts / limits.)
 *  - IMPORTANT: Only rewrite 401 to local challenge when client has NO Authorization header.
 *    If client already has Authorization and still 401, pass through upstream 401 to avoid loops.
 */

const DOCKER_HUB = "https://registry-1.docker.io";

const CONTROL_TIMEOUT_MS = 15000;
const BLOB_TIMEOUT_MS = 180000;

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000;

function buildRoutes(hostname) {
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

      if (resp.ok || resp.status === 401 || resp.status === 307) return resp;

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
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

function allowMethods() {
  return new Response(null, { status: 405, headers: { Allow: "GET, HEAD, OPTIONS" } });
}

function addCors(resp) {
  const headers = new Headers(resp.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Range");
  // Docker registry responses should not be cached
  if (!headers.has("Cache-Control")) headers.set("Cache-Control", "no-store");
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

function localChallenge(hostname) {
  // Challenge points to our /v2/auth, with DockerHub-like service
  return {
    "WWW-Authenticate": `Bearer realm="https://${hostname}/v2/auth",service="registry.docker.io"`,
    "Cache-Control": "no-store",
  };
}

function filterRequestHeaders(requestHeaders) {
  const out = new Headers();
  for (const [k, v] of requestHeaders.entries()) {
    const lk = k.toLowerCase();
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

export async function onRequest(context) {
  const request = context.request;

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
    console.error("EdgeOne Pages function error:", e);
    return addCors(json({ error: "Bad Gateway", message: e?.message || "Unknown error" }, 502));
  }
}

async function handleRequest(request, url) {
  if (url.pathname === "/") {
    return addCors(Response.redirect(`${url.protocol}//${url.host}/v2/`, 301));
  }

  const routes = buildRoutes(url.hostname);
  const upstream = routes[url.hostname];
  if (!upstream) {
    return addCors(json({ message: "Host not allowed", routes }, 404));
  }

  const isDockerHub = upstream === DOCKER_HUB;
  const authz = request.headers.get("Authorization");

  if (url.pathname === "/v2") {
    const u = new URL(url.toString());
    u.pathname = "/v2/";
    return addCors(Response.redirect(u.toString(), 301));
  }

  // /v2/ ping
  if (url.pathname === "/v2/") {
    const pingUrl = new URL(upstream + "/v2/");
    const headers = new Headers();
    if (authz) headers.set("Authorization", authz);

    const resp = await fetchWithRetry(pingUrl.toString(), {
      method: request.method, // HEAD/GET
      headers,
      redirect: "follow",
    });

    // Only challenge when client has no auth
    if (resp.status === 401 && !authz) {
      // minimal body (some clients don't care); JSON is fine, but keep it small
      return addCors(json({ message: "UNAUTHORIZED" }, 401, localChallenge(url.hostname)));
    }
    return addCors(resp);
  }

  // /v2/auth - token proxy
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

    let scope = url.searchParams.get("scope");
    if (scope && isDockerHub) {
      // repository:hello-world:pull -> repository:library/hello-world:pull
      const parts = scope.split(":");
      if (parts.length === 3 && !parts[1].includes("/")) {
        parts[1] = "library/" + parts[1];
        scope = parts.join(":");
      }
    }

    const tokenResp = await fetchToken(wwwAuth, scope, authz);
    // Ensure no-store (token responses should not be cached)
    const h = new Headers(tokenResp.headers);
    h.set("Cache-Control", "no-store");
    return addCors(new Response(tokenResp.body, { status: tokenResp.status, headers: h }));
  }

  // library/ prefix for single-segment repos
  if (isDockerHub && needsLibraryPrefix(url.pathname)) {
    const redirectUrl = withLibraryPrefix(new URL(url.toString()));
    return addCors(Response.redirect(redirectUrl.toString(), 301));
  }

  // Forward request
  const newUrl = new URL(upstream + url.pathname + (url.search || ""));
  const headers = filterRequestHeaders(request.headers);

  const newReq = new Request(newUrl.toString(), {
    method: request.method,
    headers,
    redirect: isDockerHub ? "manual" : "follow",
  });

  const timeout = isBlobRequest(url.pathname) ? BLOB_TIMEOUT_MS : CONTROL_TIMEOUT_MS;
  const resp = await fetchWithRetry(newReq, { timeout });

  // If upstream returns 401:
  // - if client has no Authorization: respond with local challenge (to /v2/auth)
  // - if client already has Authorization: pass-through upstream 401 (do NOT re-challenge)
  if (resp.status === 401) {
    if (!authz) {
      return addCors(json({ message: "UNAUTHORIZED" }, 401, localChallenge(url.hostname)));
    }
    return addCors(resp);
  }

  // CRITICAL: For blobs, do NOT fetch the 307 Location in Pages. Pass it to the Docker client.
  // Docker client will follow Location and download from the blob store directly.
  if (isDockerHub && resp.status === 307 && isBlobRequest(url.pathname)) {
    const h = new Headers(resp.headers);
    h.set("Cache-Control", "no-store");
    return addCors(new Response(null, { status: 307, headers: h }));
  }

  // For non-blob 307 (rare), just pass through
  if (isDockerHub && resp.status === 307) {
    const h = new Headers(resp.headers);
    h.set("Cache-Control", "no-store");
    return addCors(new Response(resp.body, { status: 307, headers: h }));
  }

  // Normal pass-through, enforce no-store
  const h = new Headers(resp.headers);
  if (!h.has("Cache-Control")) h.set("Cache-Control", "no-store");
  return addCors(new Response(resp.body, { status: resp.status, headers: h }));
}
