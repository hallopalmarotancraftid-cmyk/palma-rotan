const WORKER_ORIGIN = "https://palma-rotan-api-staging.hallo-palmarotancraft-id.workers.dev";

function proxyHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("x-palma-api-proxy", "pages-advanced-worker");
  return headers;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      const target = WORKER_ORIGIN + url.pathname + url.search;
      const headers = new Headers(request.headers);
      headers.delete("host");
      headers.delete("content-length");

      try {
        const response = await fetch(target, {
          method: request.method,
          headers,
          body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
          redirect: "manual"
        });

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: proxyHeaders(response)
        });
      } catch (error) {
        return new Response(JSON.stringify({
          error: "API proxy gagal terhubung ke Worker",
          detail: String(error?.message || error)
        }), {
          status: 502,
          headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            "x-palma-api-proxy": "pages-advanced-worker"
          }
        });
      }
    }

    return env.ASSETS.fetch(request);
  }
};
