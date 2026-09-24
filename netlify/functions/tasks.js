import { boards, json, readJson, currentUserId, cleanTasks } from "../lib/auth.js";

export default async (req) => {
  const userId = currentUserId(req);
  if (!userId) return json({ ok: false, error: "unauthorized" }, 401);

  if (req.method === "GET") {
    const board = await boards().get(userId, { type: "json" });
    return json({ ok: true, tasks: board?.tasks || [] });
  }

  if (req.method === "PUT") {
    const body = await readJson(req);
    const tasks = cleanTasks(body?.tasks);
    if (!tasks) return json({ ok: false, error: "invalid_tasks" }, 400);
    await boards().setJSON(userId, { tasks });
    return json({ ok: true });
  }

  return json({ ok: false }, 405);
};

export const config = { path: "/api/tasks" };
