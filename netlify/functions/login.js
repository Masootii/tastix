import crypto from "node:crypto";

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ ok: false, error: "bad request" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const sitePassword = Netlify.env.get("SITE_PASSWORD");
  const authSecret = Netlify.env.get("AUTH_SECRET");

  if (!sitePassword || !authSecret) {
    return new Response(JSON.stringify({ ok: false, error: "server not configured" }), {
      status: 500,
      headers: { "content-type": "application/json" },
    });
  }

  if (body.password !== sitePassword) {
    return new Response(JSON.stringify({ ok: false }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  }

  const expires = Date.now() + 1000 * 60 * 60 * 24 * 30;
  const sig = crypto.createHmac("sha256", authSecret).update(String(expires)).digest("hex");
  const token = `${expires}.${sig}`;

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "set-cookie": `tastix_auth=${token}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`,
    },
  });
};

export const config = { path: "/api/login" };
