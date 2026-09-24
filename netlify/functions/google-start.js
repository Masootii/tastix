import crypto from "node:crypto";
import { redirect } from "../lib/auth.js";

export default async (req) => {
  const clientId = Netlify.env.get("GOOGLE_CLIENT_ID");
  if (!clientId || !Netlify.env.get("GOOGLE_CLIENT_SECRET")) {
    return redirect("/#auth-error=google-config");
  }

  const state = crypto.randomBytes(16).toString("hex");
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: `${new URL(req.url).origin}/api/auth/google/callback`,
    response_type: "code",
    scope: "openid email",
    state,
    prompt: "select_account",
  });

  return redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, [
    `tastix_oauth_state=${state}; Path=/api/auth/google; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  ]);
};

export const config = { path: "/api/auth/google" };
