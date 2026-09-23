import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

function getCookie(req, name) {
  const header = req.headers.get("cookie") || "";
  const match = header.match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return match ? match[1] : null;
}

function isValidToken(token, secret) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [expiresStr, sig] = parts;
  const expires = Number(expiresStr);
  if (!Number.isFinite(expires) || Date.now() > expires) return false;
  const expected = crypto.createHmac("sha256", secret).update(expiresStr).digest("hex");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export default async (req) => {
  const authSecret = Netlify.env.get("AUTH_SECRET");
  const token = getCookie(req, "tastix_auth");

  if (!authSecret || !isValidToken(token, authSecret)) {
    return new Response("Unauthorized", { status: 401 });
  }

  if (req.method === "HEAD") {
    return new Response(null, { status: 200 });
  }

  const store = getStore("protected-media");
  const blob = await store.get("theme.mp3", { type: "arrayBuffer" });

  if (!blob) {
    return new Response("Not found", { status: 404 });
  }

  return new Response(blob, {
    status: 200,
    headers: {
      "content-type": "audio/mpeg",
      "cache-control": "private, no-store",
    },
  });
};

export const config = { path: "/api/audio" };
