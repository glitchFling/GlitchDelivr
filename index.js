import AccessGate from './libs/AccessGate.js';
console.log("AccessGate import:", AccessGate);
export default {
  async fetch(request, env, ctx) {
    // --- 0. Initialize AccessGate with runtime config ---
    AccessGate.config = {
      ...AccessGate.config,
      adminToken: env.ACCESS_GATE_ADMIN_TOKEN || "",
      adminTokenHeader: "x-access-gate-token",
      adminCheckEndpoint: env.ADMIN_CHECK_ENDPOINT || "/access/is-admin"
    };

    // --- 1. Extract admin token from request ---
    const token =
      request.headers.get(AccessGate.config.adminTokenHeader) ||
      request.headers.get("ACCESS_GATE_ADMIN_TOKEN") ||
      "";

    // --- 2. Validate admin token using AccessGate ---
    const isAdmin = await AccessGate.isAdmin(token);

    if (!isAdmin) {
      return new Response("Forbidden: Admin Access Only", {
        status: 200,
        headers: { "Content-Type": "text/plain" }
      });
    }

    // --- 3. Continue with CDN logic ---
    const url = new URL(request.url);
    const key = url.pathname.slice(1);

    // Landing page (still admin-only)
    if (key === "") {
      return new Response("glitchdelivr CDN (admin-only) is active.", {
        status: 200
      });
    }
    if (url.pathname === "/debug") {
  return new Response(JSON.stringify({
    accessGateType: typeof AccessGate,
    accessGateKeys: Object.keys(AccessGate)
  }, null, 2), {
    headers: { "Content-Type": "application/json" }
  });
}

    // Edge cache
    const cache = caches.default;
    let response = await cache.match(request);
    if (response) return response;

    // Fetch from R2
    const object = await env.GLITCHDELIVR_R2.get(key);
    if (!object) {
      return new Response("Object Not Found", {
        status: 404,
        headers: { "Content-Type": "text/plain" }
      });
    }

    // Build headers
    const headers = new Headers();
    object.writeHttpMetadata(headers);

    if (!headers.has("Content-Type")) {
      headers.set("Content-Type", "application/octet-stream");
    }

    headers.set("etag", object.httpEtag);
    headers.set("Cache-Control", "public, max-age=3600");

    response = new Response(object.body, { headers });

    // Cache and return
    ctx.waitUntil(cache.put(request, response.clone()));
    return response;
  }
};
