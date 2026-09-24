import { getStore } from "@netlify/blobs";
import { currentUserId } from "../lib/auth.js";

export default async (req) => {
  if (!currentUserId(req)) {
    return new Response("Unauthorized", { status: 401 });
  }

  if (req.method === "HEAD") {
    return new Response(null, { status: 200 });
  }

  const store = getStore("protected-media");
  const manifest = await store.get("theme-manifest", { type: "json" });

  if (!manifest || !manifest.parts) {
    return new Response("Not found", { status: 404 });
  }

  const buffers = [];
  for (let i = 0; i < manifest.parts; i++) {
    const part = await store.get(`theme-part-${i}`, { type: "arrayBuffer" });
    if (!part) {
      return new Response("Not found", { status: 404 });
    }
    buffers.push(new Uint8Array(part));
  }

  const combined = new Uint8Array(manifest.totalBytes);
  let offset = 0;
  for (const buf of buffers) {
    combined.set(buf, offset);
    offset += buf.byteLength;
  }

  return new Response(combined, {
    status: 200,
    headers: {
      "content-type": "audio/mpeg",
      "cache-control": "private, no-store",
    },
  });
};

export const config = { path: "/api/audio" };
