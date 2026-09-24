import crypto from "node:crypto";
import {
  users, resets, json, readJson, normalizeEmail, emailKey, resetKey,
  lockedMinutes, recordAttempt, EMAIL_RE,
} from "../lib/auth.js";
import { mailConfigured, sendMail } from "../lib/mail.js";

const TOKEN_TTL_MS = 30 * 60 * 1000;
const MAX_PER_EMAIL = 3;
const MAX_PER_IP = 10;

function resetEmail(link) {
  const text = [
    "برای گذاشتن رمز جدید در Tastix روی این لینک بزن (تا ۳۰ دقیقه معتبره):",
    link,
    "",
    "اگه تو درخواست بازیابی رمز ندادی، این ایمیل رو نادیده بگیر؛ رمزت تغییری نمی‌کنه.",
  ].join("\n");
  const html = `<div dir="rtl" style="font-family:Tahoma,sans-serif;background:#05080a;color:#dfffec;padding:28px;border-radius:6px">
  <h2 style="color:#3dffa0;margin:0 0 12px">بازیابی رمز Tastix</h2>
  <p>برای گذاشتن رمز جدید روی دکمه‌ی زیر بزن. این لینک تا ۳۰ دقیقه معتبره و فقط یک بار کار می‌کنه.</p>
  <p style="margin:22px 0"><a href="${link}" style="background:#1c8f5c;color:#04140b;padding:10px 22px;border-radius:3px;text-decoration:none;font-weight:bold">گذاشتن رمز جدید</a></p>
  <p style="color:#7fa694;font-size:13px">اگه تو درخواست بازیابی رمز ندادی، این ایمیل رو نادیده بگیر؛ رمزت تغییری نمی‌کنه.</p>
</div>`;
  return { subject: "بازیابی رمز Tastix", text, html };
}

export default async (req, context) => {
  if (req.method !== "POST") return json({ ok: false }, 405);
  if (!mailConfigured()) return json({ ok: false, error: "mail_not_configured" }, 503);

  const body = await readJson(req);
  const email = normalizeEmail(body?.email);
  if (email.length > 254 || !EMAIL_RE.test(email)) {
    return json({ ok: false, error: "invalid_email" }, 400);
  }

  const key = emailKey(email);
  const emailThrottle = `reset-${key}`;
  const ipThrottle = context?.ip ? `reset-ip-${context.ip}` : null;
  const retryAfter = Math.max(
    await lockedMinutes(emailThrottle),
    ipThrottle ? await lockedMinutes(ipThrottle) : 0,
  );
  if (retryAfter) return json({ ok: false, error: "too_many_attempts", retryAfter }, 429);

  await recordAttempt(emailThrottle, MAX_PER_EMAIL);
  if (ipThrottle) await recordAttempt(ipThrottle, MAX_PER_IP);

  // Same response whether or not the account exists, so this can't be used
  // to discover who has signed up.
  const user = await users().get(key, { type: "json" });
  if (!user) return json({ ok: true });

  const token = crypto.randomBytes(32).toString("base64url");
  await resets().setJSON(resetKey(token), { emailKey: key, expires: Date.now() + TOKEN_TTL_MS });

  try {
    await sendMail({ to: user.email, ...resetEmail(`${new URL(req.url).origin}/#reset=${token}`) });
  } catch (err) {
    console.error("reset email failed:", err);
    return json({ ok: false, error: "mail_failed" }, 502);
  }
  return json({ ok: true });
};

export const config = { path: "/api/reset-request" };
