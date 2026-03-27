import AccessGate from './libs/AccessGate.js';

export default {
  async fetch(request, env, ctx) {
    // Return the maintenance response immediately
    return new Response(env.GLITCHDELIVR_ARMONO, {
      status: 503,
      headers: { "Content-Type": "text/plain" }
    });

    // The code below is currently unreachable but now syntactically correct
    const UserID = await AccessGate._deterministicFallbackId();

if (UserID === "det_22d9ac0bfd878d0db119826b1078e088a778f26a0d074f2b") {
  // Does Nothing, Move On.
} else {
  return new Response("Unauthorized: Default AccessGate ID detected.", {
    status: 401,
    headers: { "Content-Type": "text/plain" }
  });
}
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
