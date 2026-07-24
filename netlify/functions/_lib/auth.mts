import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

// ===== Password hashing (Node built-in scrypt, no external deps) =====
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string | undefined | null): boolean {
  if (!stored || !password) return false;
  const parts = stored.split(":");
  if (parts.length !== 2) return false;
  const [salt, hash] = parts;
  try {
    const hashToVerify = crypto.scryptSync(password, salt, 64).toString("hex");
    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(hashToVerify, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// ===== Session store =====
export interface SessionRecord {
  role: "admin" | "agent";
  agentId?: string;
  createdAt: number;
}

function sessionsStore() {
  return getStore({ name: "pcs-sessions", consistency: "strong" });
}

export async function createSession(record: SessionRecord): Promise<string> {
  const token = crypto.randomBytes(32).toString("hex");
  await sessionsStore().setJSON(token, record);
  return token;
}

export async function getSession(token: string | null): Promise<SessionRecord | null> {
  if (!token) return null;
  const rec = await sessionsStore().get(token, { type: "json" });
  return (rec as SessionRecord) || null;
}

export async function destroySession(token: string): Promise<void> {
  await sessionsStore().delete(token);
}

export function extractToken(req: Request): string | null {
  const header = req.headers.get("authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1] : null;
}

export async function requireSession(req: Request): Promise<SessionRecord | null> {
  const token = extractToken(req);
  return getSession(token);
}

// ===== Workspace (shared operational data) store =====
export function workspaceStore() {
  return getStore({ name: "pcs-workspace", consistency: "strong" });
}

export function defaultWorkspace(adminPasswordHash: string) {
  return {
    agents: [],
    commissions: [],
    bobClients: [],
    customResources: [],
    notifications: [],
    enrollments: [],
    adminPasswordHash,
    resourceContentVersion: 0,
    _version: 0,
  };
}

// Strip anything that should never be sent to a browser (password hashes).
export function sanitizeForClient(workspace: any) {
  const clone = JSON.parse(JSON.stringify(workspace || {}));
  delete clone.adminPasswordHash;
  if (Array.isArray(clone.agents)) {
    clone.agents = clone.agents.map((a: any) => {
      if (a && a.credentials) {
        const { passwordHash, ...restCreds } = a.credentials;
        return { ...a, credentials: restCreds };
      }
      return a;
    });
  }
  return clone;
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
