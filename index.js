import AccessGate from './libs/AccessGate.js';

export default {
  async fetch(request, env, ctx) {
    // --- ADDED BACK: Your exact response logic ---
    // This will now trigger on every request before the CDN logic runs
    console.log("AccessGate import:", AccessGate);
    return new Response("AccessGate import: " + JSON.stringify(AccessGate), {
      status: 200
    });

    // --- The rest of your code (will not be reached because of the return above) ---
    AccessGate.config = {
      ...AccessGate.config,
      adminToken: env.ACCESS_GATE_ADMIN_TOKEN || "",
      adminTokenHeader: "x-access-gate-token",
      adminCheckEndpoint: env.ADMIN_CHECK_ENDPOINT || "/access/is-admin"
    };

    const token =
      request.headers.get(AccessGate.config.adminTokenHeader) ||
      request.headers.get("ACCESS_GATE_ADMIN_TOKEN") ||
      "";

    const isAdmin = await AccessGate.isAdmin(token);
    const url = new URL(request.url);
    const key = url.pathname.slice(1);

    if (key === "") {
      return new Response("glitchdelivr CDN (admin-only) is active.", {
        status: 200
      });
    }

    const cache = caches.default;
    let response = await cache.match(request);
    if (response) return response;

    const object = await env.GLITCHDELIVR_R2.get(key);
    if (!object) {
      return new Response("Object Not Found", {
        status: 404,
        headers: { "Content-Type": "text/plain" }
      });
    }

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("etag", object.httpEtag);
    headers.set("Cache-Control", "public, max-age=3600");

    response = new Response(object.body, { headers });
    ctx.waitUntil(cache.put(request, response.clone()));
    return response;
  }
};
