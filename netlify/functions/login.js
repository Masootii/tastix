import {
  users, boards, json, readJson, sessionCookie, verifyPassword,
  normalizeEmail, emailKey,
} from "../lib/auth.js";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false }, 405);

  const body = await readJson(req);
  if (!body) return json({ ok: false, error: "bad_request" }, 400);

  const email = normalizeEmail(body.email);
  const password = typeof body.password === "string" ? body.password : "";

  const user = email ? await users().get(emailKey(email), { type: "json" }) : null;
  if (!user || !user.password || !verifyPassword(password, user.password)) {
    return json({ ok: false, error: "invalid_credentials" }, 401);
  }

  const board = await boards().get(user.id, { type: "json" });
  return json(
    { ok: true, email: user.email, tasks: board?.tasks || [] },
    200,
    { "set-cookie": sessionCookie(user.id) },
  );
};

export const config = { path: "/api/login" };
