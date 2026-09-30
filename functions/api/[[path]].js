const WORKER_ORIGIN = "https://palma-rotan-api-staging.hallo-palmarotancraft-id.workers.dev";

export async function onRequest(context) {
  const request = context.request;
  const url = new URL(request.url);
  const target = WORKER_ORIGIN + url.pathname + url.search;
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");

  const init = {
    method: request.method,
    headers,
    redirect: "manual"
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = request.body;
  }

  const response = await fetch(target, init);
  const outHeaders = new Headers(response.headers);
  outHeaders.set("cache-control", "no-store");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: outHeaders
  });
}
