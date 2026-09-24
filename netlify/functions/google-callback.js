import crypto from "node:crypto";
import {
  users, boards, redirect, readCookie, sessionCookie,
  emailKey, userIndexKey, normalizeEmail,
} from "../lib/auth.js";

const clearState = "tastix_oauth_state=; Path=/api/auth/google; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
const fail = (reason) => redirect(`/#auth-error=${reason}`, [clearState]);

function sameState(a, b) {
  return Boolean(a && b) && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// The ID token comes straight from Google's token endpoint over TLS,
// so its signature doesn't need separate verification; the claims still do.
async function fetchIdClaims(code, clientId, clientSecret, redirectUri) {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });
  if (!res.ok) return null;
  const { id_token: idToken } = await res.json();
  return JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
}

export default async (req) => {
  const url = new URL(req.url);
  const clientId = Netlify.env.get("GOOGLE_CLIENT_ID");
  const clientSecret = Netlify.env.get("GOOGLE_CLIENT_SECRET");
  if (!clientId || !clientSecret) return fail("google-config");

  if (!sameState(url.searchParams.get("state"), readCookie(req, "tastix_oauth_state"))) {
    return fail("google");
  }
  if (url.searchParams.get("error")) return fail("google-cancelled");

  const code = url.searchParams.get("code");
  if (!code) return fail("google");

  let claims;
  try {
    claims = await fetchIdClaims(code, clientId, clientSecret, `${url.origin}/api/auth/google/callback`);
  } catch {
    claims = null;
  }
  const trustedIssuer = claims && (claims.iss === "https://accounts.google.com" || claims.iss === "accounts.google.com");
  if (!trustedIssuer || claims.aud !== clientId || claims.email_verified !== true || !(claims.exp * 1000 > Date.now())) {
    return fail("google");
  }

  const email = normalizeEmail(claims.email);
  if (!email) return fail("google");

  const key = emailKey(email);
  let user = await users().get(key, { type: "json" });
  const isNew = !user;

  if (isNew) {
    user = {
      id: crypto.randomBytes(12).toString("hex"),
      email,
      password: null,
      googleSub: claims.sub,
      createdAt: new Date().toISOString(),
    };
    await users().setJSON(key, user);
    await boards().setJSON(user.id, { tasks: [] });
  } else if (!user.googleSub) {
    // Password signups never proved they own the email; now that Google has,
    // drop that password so whoever set it can't keep using the account.
    user.googleSub = claims.sub;
    user.password = null;
    await users().setJSON(key, user);
  }
  await users().setJSON(userIndexKey(user.id), { email });

  return redirect(isNew ? "/#google-new" : "/#google", [sessionCookie(user.id), clearState]);
};

export const config = { path: "/api/auth/google/callback" };
