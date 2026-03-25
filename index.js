export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const key = url.pathname.slice(1);

    // 1. Basic landing message
    if (key === "") {
      return new Response("glitchdelivr CDN is active.", { status: 200 });
    }

    // 2. Check the Edge Cache
    const cache = caches.default;
    let response = await cache.match(request);

    if (response) {
      return response;
    }

    // 3. Fetch from your specific R2 binding
    const object = await env.GLITCHDELIVR_R2.get(key);

    if (object === null) {
      return new Response("Object Not Found", { 
        status: 404,
        headers: { "Content-Type": "text/plain" }
      });
    }

    // 4. Construct response with R2 metadata
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("etag", object.httpEtag);
    
    // Cache for 1 hour at the Edge and in the Browser
    headers.set("Cache-Control", "public, max-age=3600");

    response = new Response(object.body, {
      headers,
    });

    // 5. Save to Cache and Return
    ctx.waitUntil(cache.put(request, response.clone()));

    return response;
  },
};
