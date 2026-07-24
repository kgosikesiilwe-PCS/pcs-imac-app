import type { Context, Config } from "@netlify/functions";
import {
  workspaceStore,
  defaultWorkspace,
  hashPassword,
  verifyPassword,
  createSession,
  jsonResponse,
} from "./_lib/auth.mts";

const DEFAULT_ADMIN_PASSWORD = "admin123";

export default async (req: Request, context: Context) => {
  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "Invalid request body" }, 400);
  }

  const role = body?.role;
  const store = workspaceStore();

  let workspace = await store.get("workspace", { type: "json" });
  if (!workspace) {
    // First-ever login on a fresh deploy: bootstrap with the same default
    // admin password the app has always shipped with.
    workspace = defaultWorkspace(hashPassword(DEFAULT_ADMIN_PASSWORD));
    await store.setJSON("workspace", workspace);
  }

  if (role === "admin") {
    const password = body?.password || "";
    if (verifyPassword(password, (workspace as any).adminPasswordHash)) {
      const token = await createSession({ role: "admin", createdAt: Date.now() });
      return jsonResponse({ token, role: "admin" });
    }
    return jsonResponse({ error: "Incorrect admin password." }, 401);
  }

  if (role === "agent") {
    const username = String(body?.username || "").trim().toLowerCase();
    const password = body?.password || "";
    const agents = Array.isArray((workspace as any).agents) ? (workspace as any).agents : [];
    const agent = agents.find(
      (a: any) =>
        a.credentials &&
        a.credentials.username &&
        String(a.credentials.username).toLowerCase() === username &&
        a.credentials.enabled === "enabled" &&
        verifyPassword(password, a.credentials.passwordHash)
    );
    if (agent) {
      const token = await createSession({ role: "agent", agentId: agent.id, createdAt: Date.now() });
      return jsonResponse({ token, role: "agent", agentId: agent.id });
    }
    return jsonResponse({ error: "Incorrect username or password, or portal access is disabled." }, 401);
  }

  return jsonResponse({ error: "Invalid role" }, 400);
};

export const config: Config = {
  path: "/api/login",
};
