import { json, clearedCookie } from "../lib/auth.js";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false }, 405);
  return json({ ok: true }, 200, { "set-cookie": clearedCookie });
};

export const config = { path: "/api/logout" };
