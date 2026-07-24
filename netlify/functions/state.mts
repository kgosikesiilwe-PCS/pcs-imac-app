import type { Context, Config } from "@netlify/functions";
import {
  workspaceStore,
  defaultWorkspace,
  hashPassword,
  verifyPassword,
  requireSession,
  sanitizeForClient,
  generateSetupCode,
  jsonResponse,
} from "./_lib/auth.mts";

const DEFAULT_ADMIN_PASSWORD_HASH_SEED = "admin123";

export default async (req: Request, context: Context) => {
  const session = await requireSession(req);
  if (!session) {
    return jsonResponse({ error: "Not authenticated" }, 401);
  }

  const store = workspaceStore();

  if (req.method === "GET") {
    let workspace = await store.get("workspace", { type: "json" });
    if (!workspace) {
      workspace = defaultWorkspace(hashPassword(DEFAULT_ADMIN_PASSWORD_HASH_SEED));
      await store.setJSON("workspace", workspace);
    }
    return jsonResponse({
      state: sanitizeForClient(workspace, session.role),
      version: (workspace as any)._version || 0,
      role: session.role,
      agentId: session.agentId || null,
    });
  }

  if (req.method === "POST") {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: "Invalid request body" }, 400);
    }

    // Self-service credential change: requires the CURRENT password to be
    // verified server-side against the stored hash (the client never has
    // access to any password hash, so this can't be checked client-side).
    if (body?.action === "change-credentials") {
      if (session.role !== "agent" || !session.agentId) {
        return jsonResponse({ error: "Only iMACs can use this action" }, 403);
      }
      const currentPassword = body?.currentPassword || "";
      const newUsername = String(body?.newUsername || "").trim();
      const newPassword = body?.newPassword || "";
      let existing: any = await store.get("workspace", { type: "json" });
      if (!existing) existing = defaultWorkspace(hashPassword(DEFAULT_ADMIN_PASSWORD_HASH_SEED));
      const agents = Array.isArray(existing.agents) ? existing.agents : [];
      const agent = agents.find((a: any) => a.id === session.agentId);
      if (!agent) return jsonResponse({ error: "Account not found" }, 404);
      if (!verifyPassword(currentPassword, agent.credentials && agent.credentials.passwordHash)) {
        return jsonResponse({ error: "Current password is incorrect" }, 401);
      }
      if (!newUsername) return jsonResponse({ error: "Username cannot be blank" }, 400);
      const taken = agents.some(
        (a: any) =>
          a.id !== agent.id &&
          a.credentials &&
          a.credentials.username &&
          a.credentials.username.toLowerCase() === newUsername.toLowerCase()
      );
      if (taken) return jsonResponse({ error: "That username is already in use" }, 409);
      if (newPassword) {
        if (newPassword.length < 4) {
          return jsonResponse({ error: "New password must be at least 4 characters" }, 400);
        }
        agent.credentials.passwordHash = hashPassword(newPassword);
      }
      agent.credentials.username = newUsername;
      existing._version = (existing._version || 0) + 1;
      await store.setJSON("workspace", existing);
      return jsonResponse({ state: sanitizeForClient(existing, session.role), version: existing._version });
    }

    const incoming = body?.state;
    const baseVersion = body?.baseVersion;
    if (!incoming || typeof incoming !== "object") {
      return jsonResponse({ error: "Missing state" }, 400);
    }

    let existing: any = await store.get("workspace", { type: "json" });
    if (!existing) {
      existing = defaultWorkspace(hashPassword(DEFAULT_ADMIN_PASSWORD_HASH_SEED));
    }

    // Optimistic concurrency: reject if someone else saved since this client last read.
    const existingVersion = existing._version || 0;
    if (typeof baseVersion === "number" && baseVersion !== existingVersion) {
      return jsonResponse(
        {
          error: "conflict",
          message: "This data was changed elsewhere since you last loaded it.",
          state: sanitizeForClient(existing, session.role),
          version: existingVersion,
        },
        409
      );
    }

    // Agents only allowed to save their own agent record's fields, plus
    // the shared collections they're permitted to touch (referrals, own
    // certifications/documents, etc). Admin can save everything. This is a
    // light-touch guard, not full per-field validation.
    if (session.role === "agent") {
      const existingAgents = Array.isArray(existing.agents) ? existing.agents : [];
      const others = existingAgents.filter((a: any) => a.id !== session.agentId);
      const incomingOwn = (Array.isArray(incoming.agents) ? incoming.agents : []).find(
        (a: any) => a.id === session.agentId
      );
      if (!incomingOwn) {
        return jsonResponse({ error: "Agents may only update their own record" }, 403);
      }
      incoming.agents = [...others, incomingOwn];
      // Agents cannot rewrite other agents' referral bonuses, credentials page state, etc.
      // (customResources/enrollments/notifications remain as submitted since agents
      // legitimately create/edit their own referrals and read/answer shared study
      // material; admin-only collections below are restored from the existing copy.)
      incoming.commissions = existing.commissions;
      incoming.customResources = existing.customResources;
      incoming.resourceContentVersion = existing.resourceContentVersion;
    }

    // Password handling: hash any plaintext password the client just set;
    // otherwise preserve whatever hash is already on file.
    let adminPasswordHash = existing.adminPasswordHash;
    if (incoming.adminPassword) {
      adminPasswordHash = hashPassword(incoming.adminPassword);
    }

    const existingAgentsById = Object.fromEntries(
      (Array.isArray(existing.agents) ? existing.agents : []).map((a: any) => [a.id, a])
    );
    const mergedAgents = (Array.isArray(incoming.agents) ? incoming.agents : []).map((a: any) => {
      const prev = existingAgentsById[a.id];
      const creds = { ...(a.credentials || {}) };
      if (creds.password) {
        creds.passwordHash = hashPassword(creds.password);
        delete creds.password;
      } else if (prev && prev.credentials && prev.credentials.passwordHash) {
        creds.passwordHash = prev.credentials.passwordHash;
      }
      const out = { ...a, credentials: creds };
      if (creds.passwordHash) {
        // Account is fully set up (or just got a password from admin) — no
        // setup code needed any more.
        delete out.setupCode;
      } else if (prev && prev.setupCode) {
        // Still pending self-service setup — keep the same code so a code
        // already shared with the iMAC doesn't silently stop working.
        out.setupCode = prev.setupCode;
      } else if (!creds.username) {
        // Brand-new iMAC created with no credentials at all — generate their
        // one-time setup code now.
        out.setupCode = generateSetupCode();
      }
      return out;
    });

    const merged = {
      ...incoming,
      agents: mergedAgents,
      adminPasswordHash,
      _version: existingVersion + 1,
    };
    delete (merged as any).adminPassword;

    await store.setJSON("workspace", merged);

    return jsonResponse({ state: sanitizeForClient(merged, session.role), version: merged._version });
  }

  return jsonResponse({ error: "Method not allowed" }, 405);
};

export const config: Config = {
  path: "/api/state",
};
