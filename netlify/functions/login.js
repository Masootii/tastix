import {
  users, boards, json, readJson, sessionCookie, verifyPassword,
  normalizeEmail, emailKey, lockedMinutes, recordAttempt, clearAttempts,
} from "../lib/auth.js";

const MAX_FAILS_PER_EMAIL = 5;
const MAX_FAILS_PER_IP = 20;

export default async (req, context) => {
  if (req.method !== "POST") return json({ ok: false }, 405);

  const body = await readJson(req);
  if (!body) return json({ ok: false, error: "bad_request" }, 400);

  const email = normalizeEmail(body.email);
  const password = typeof body.password === "string" ? body.password : "";
  if (!email) return json({ ok: false, error: "invalid_credentials" }, 401);

  const key = emailKey(email);
  const emailThrottle = `login-${key}`;
  const ipThrottle = context?.ip ? `login-ip-${context.ip}` : null;

  const retryAfter = Math.max(
    await lockedMinutes(emailThrottle),
    ipThrottle ? await lockedMinutes(ipThrottle) : 0,
  );
  if (retryAfter) {
    return json({ ok: false, error: "too_many_attempts", retryAfter }, 429);
  }

  const user = await users().get(key, { type: "json" });
  if (!user || !user.password || !verifyPassword(password, user.password)) {
    await recordAttempt(emailThrottle, MAX_FAILS_PER_EMAIL);
    if (ipThrottle) await recordAttempt(ipThrottle, MAX_FAILS_PER_IP);
    return json({ ok: false, error: "invalid_credentials" }, 401);
  }

  await clearAttempts(emailThrottle);
  const board = await boards().get(user.id, { type: "json" });
  return json(
    { ok: true, email: user.email, tasks: board?.tasks || [] },
    200,
    { "set-cookie": sessionCookie(user.id) },
  );
};

export const config = { path: "/api/login" };
