import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

const COOKIE = "tastix_auth";
const SESSION_MS = 1000 * 60 * 60 * 2;

export const STATUSES = ["planned", "doing", "done"];
export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Default Blobs reads are eventually consistent (up to ~60s stale), which
// would show old boards and let duplicate signups slip through.
export const users = () => getStore({ name: "users", consistency: "strong" });
export const boards = () => getStore({ name: "boards", consistency: "strong" });

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export function redirect(location, cookies = []) {
  const headers = new Headers({ location });
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(null, { status: 302, headers });
}

export function readCookie(req, name) {
  const match = (req.headers.get("cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return match ? match[1] : null;
}

export const userIndexKey = (userId) => `user-${userId}`;

export async function readJson(req) {
  try {
    return await req.json();
  } catch {
    return null;
  }
}

function sign(payload) {
  const secret = Netlify.env.get("AUTH_SECRET");
  if (!secret) throw new Error("AUTH_SECRET is not set");
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

export function sessionCookie(userId) {
  const payload = `${userId}.${Date.now() + SESSION_MS}`;
  return `${COOKIE}=${payload}.${sign(payload)}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

export const clearedCookie = `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

export function currentUserId(req) {
  const token = readCookie(req, COOKIE);
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [userId, expires, sig] = parts;
  if (!(Number(expires) > Date.now())) return null;
  const expected = Buffer.from(sign(`${userId}.${expires}`));
  const given = Buffer.from(sig);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  return userId;
}

export function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

export function emailKey(email) {
  return "email-" + crypto.createHash("sha256").update(email).digest("hex");
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

export function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(":");
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, "hex"), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

export function cleanTasks(input) {
  if (!Array.isArray(input) || input.length > 500) return null;
  const out = [];
  for (const t of input) {
    if (!t || typeof t.id !== "string" || t.id.length > 64) return null;
    if (typeof t.text !== "string" || !STATUSES.includes(t.status)) return null;
    const text = t.text.trim().slice(0, 140);
    if (!text) return null;
    out.push({ id: t.id, text, status: t.status });
  }
  return out;
}
