import { getStore } from "@netlify/blobs";

export default async (req) => {
  const adminSecret = Netlify.env.get("ADMIN_SECRET");
  if (!adminSecret || req.headers.get("x-admin-secret") !== adminSecret) {
    return new Response("Forbidden", { status: 403 });
  }

  const store = getStore("protected-media");
  const buf = await req.arrayBuffer();
  await store.set("theme.mp3", buf);

  return new Response(JSON.stringify({ ok: true, bytes: buf.byteLength }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

export const config = { path: "/api/admin-upload" };
