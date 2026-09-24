import crypto from "node:crypto";
import {
  users, boards, json, readJson, sessionCookie, hashPassword,
  cleanTasks, normalizeEmail, emailKey, userIndexKey, EMAIL_RE,
} from "../lib/auth.js";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false }, 405);

  const body = await readJson(req);
  if (!body) return json({ ok: false, error: "bad_request" }, 400);

  const email = normalizeEmail(body.email);
  const password = typeof body.password === "string" ? body.password : "";

  if (email.length > 254 || !EMAIL_RE.test(email)) {
    return json({ ok: false, error: "invalid_email" }, 400);
  }
  if (password.length < 8 || password.length > 200) {
    return json({ ok: false, error: "weak_password" }, 400);
  }

  const key = emailKey(email);
  if (await users().get(key)) {
    return json({ ok: false, error: "email_taken" }, 409);
  }

  const id = crypto.randomBytes(12).toString("hex");
  await users().setJSON(key, {
    id,
    email,
    password: hashPassword(password),
    createdAt: new Date().toISOString(),
  });
  await users().setJSON(userIndexKey(id), { email });

  const tasks = cleanTasks(body.tasks) || [];
  await boards().setJSON(id, { tasks });

  return json({ ok: true, email, tasks }, 201, { "set-cookie": sessionCookie(id) });
};

export const config = { path: "/api/signup" };
