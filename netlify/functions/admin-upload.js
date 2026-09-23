import { getStore } from "@netlify/blobs";

const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "x-admin-secret, content-type",
  "access-control-allow-methods": "POST, OPTIONS",
};

export default async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const adminSecret = Netlify.env.get("ADMIN_SECRET");
  if (!adminSecret || req.headers.get("x-admin-secret") !== adminSecret) {
    return new Response("Forbidden", { status: 403, headers: CORS_HEADERS });
  }

  const url = new URL(req.url);
  const store = getStore("protected-media");

  if (url.pathname.endsWith("/manifest")) {
    const manifest = await req.json();
    await store.setJSON("theme-manifest", manifest);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json", ...CORS_HEADERS },
    });
  }

  const part = url.searchParams.get("part");
  if (part === null) {
    return new Response(JSON.stringify({ ok: false, error: "missing part" }), {
      status: 400,
      headers: { "content-type": "application/json", ...CORS_HEADERS },
    });
  }

  const buf = await req.arrayBuffer();
  await store.set(`theme-part-${part}`, buf);

  return new Response(JSON.stringify({ ok: true, part, bytes: buf.byteLength }), {
    status: 200,
    headers: { "content-type": "application/json", ...CORS_HEADERS },
  });
};

export const config = { path: ["/api/admin-upload", "/api/admin-upload/manifest"] };
