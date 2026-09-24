import {
  users, boards, resets, json, readJson, sessionCookie, hashPassword,
  resetKey, userIndexKey, clearAttempts,
} from "../lib/auth.js";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false }, 405);

  const body = await readJson(req);
  const token = typeof body?.token === "string" ? body.token : "";
  const password = typeof body?.password === "string" ? body.password : "";
  if (password.length < 8 || password.length > 200) {
    return json({ ok: false, error: "weak_password" }, 400);
  }
  if (!token || token.length > 100) return json({ ok: false, error: "invalid_token" }, 400);

  const key = resetKey(token);
  const record = await resets().get(key, { type: "json" });
  if (!record) return json({ ok: false, error: "invalid_token" }, 400);
  await resets().delete(key);
  if (record.expires < Date.now()) return json({ ok: false, error: "invalid_token" }, 400);

  const user = await users().get(record.emailKey, { type: "json" });
  if (!user) return json({ ok: false, error: "invalid_token" }, 400);

  user.password = hashPassword(password);
  await users().setJSON(record.emailKey, user);
  await users().setJSON(userIndexKey(user.id), { email: user.email });
  await clearAttempts(`login-${record.emailKey}`);

  const board = await boards().get(user.id, { type: "json" });
  return json(
    { ok: true, email: user.email, tasks: board?.tasks || [] },
    200,
    { "set-cookie": sessionCookie(user.id) },
  );
};

export const config = { path: "/api/reset-confirm" };
