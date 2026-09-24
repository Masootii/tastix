import { users, boards, json, currentUserId, userIndexKey } from "../lib/auth.js";

export default async (req) => {
  const userId = currentUserId(req);
  if (!userId) return json({ ok: false, error: "unauthorized" }, 401);

  const [profile, board] = await Promise.all([
    users().get(userIndexKey(userId), { type: "json" }),
    boards().get(userId, { type: "json" }),
  ]);
  return json({ ok: true, email: profile?.email || "", tasks: board?.tasks || [] });
};

export const config = { path: "/api/me" };
