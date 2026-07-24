import type { Context, Config } from "@netlify/functions";
import { extractToken, destroySession, jsonResponse } from "./_lib/auth.mts";

export default async (req: Request, context: Context) => {
  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }
  const token = extractToken(req);
  if (token) {
    await destroySession(token);
  }
  return jsonResponse({ ok: true });
};

export const config: Config = {
  path: "/api/logout",
};
