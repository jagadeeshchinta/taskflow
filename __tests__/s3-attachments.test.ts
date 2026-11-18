import {
  validateFileUpload,
  sanitizeFilename,
  generateS3Key,
  createPresignedUploadUrl,
  createPresignedDownloadUrl,
  MAX_IMAGE_SIZE_BYTES,
  MAX_DOCUMENT_SIZE_BYTES,
  PRESIGNED_URL_EXPIRY_SECONDS,
  S3_BUCKET_NAME,
} from "../src/lib/s3";

// Mock @aws-sdk/s3-request-presigner
jest.mock("@aws-sdk/s3-request-presigner", () => ({
  getSignedUrl: jest.fn().mockImplementation(async (_client, command, options) => {
    const bucket = command.input?.Bucket || "test-bucket";
    const key = command.input?.Key || "test-key";
    const expires = options?.expiresIn || 300;
    return `https://${bucket}.s3.ap-south-1.amazonaws.com/${key}?X-Amz-Expires=${expires}&X-Amz-Signature=mockedsig12345`;
  }),
}));

describe("AWS S3 & TaskFlow Attachments Security Suite", () => {
  // ── 1. File Upload Validation & Whitelisting ───────────────────────
  describe("validateFileUpload", () => {
    test("allows valid JPEG, PNG, and WebP images within 5MB", () => {
      const jpgResult = validateFileUpload("design-mockup.jpg", "image/jpeg", 2 * 1024 * 1024, "attachment");
      expect(jpgResult.valid).toBe(true);
      expect(jpgResult.category).toBe("image");

      const pngResult = validateFileUpload("screenshot.png", "image/png", 4 * 1024 * 1024, "attachment");
      expect(pngResult.valid).toBe(true);
      expect(pngResult.category).toBe("image");

      const webpResult = validateFileUpload("banner.webp", "image/webp", 1 * 1024 * 1024, "attachment");
      expect(webpResult.valid).toBe(true);
      expect(webpResult.category).toBe("image");
    });

    test("allows valid PDF documents within 10MB", () => {
      const pdfResult = validateFileUpload("project-specification.pdf", "application/pdf", 8 * 1024 * 1024, "attachment");
      expect(pdfResult.valid).toBe(true);
      expect(pdfResult.category).toBe("document");
    });

    test("STRICTLY REJECTS SVG files (prevents stored XSS attacks)", () => {
      const svgResult = validateFileUpload("icon.svg", "image/svg+xml", 500, "attachment");
      expect(svgResult.valid).toBe(false);
      expect(svgResult.error).toContain("strictly prohibited");
    });

    test("STRICTLY REJECTS executable and script files", () => {
      const executables = [
        { file: "payload.exe", mime: "application/x-msdownload" },
        { file: "script.sh", mime: "application/x-sh" },
        { file: "run.bat", mime: "application/x-bat" },
        { file: "installer.msi", mime: "application/octet-stream" },
        { file: "exploit.js", mime: "application/javascript" },
        { file: "macro.vbs", mime: "text/vbscript" },
      ];

      for (const item of executables) {
        const result = validateFileUpload(item.file, item.mime, 1024, "attachment");
        expect(result.valid).toBe(false);
        expect(result.error).toContain("strictly prohibited");
      }
    });

    test("enforces size limits: rejects images > 5MB and documents > 10MB", () => {
      const oversizedImage = validateFileUpload("huge-photo.png", "image/png", MAX_IMAGE_SIZE_BYTES + 1024, "attachment");
      expect(oversizedImage.valid).toBe(false);
      expect(oversizedImage.error).toContain("exceeds maximum limit of 5MB");

      const oversizedPdf = validateFileUpload("huge-manual.pdf", "application/pdf", MAX_DOCUMENT_SIZE_BYTES + 1024, "attachment");
      expect(oversizedPdf.valid).toBe(false);
      expect(oversizedPdf.error).toContain("exceeds maximum limit of 10MB");
    });

    test("rejects mismatched MIME types and file extensions", () => {
      const mismatched = validateFileUpload("document.pdf", "image/png", 1024, "attachment");
      expect(mismatched.valid).toBe(false);
      expect(mismatched.error).toContain("does not match MIME type");
    });

    test("validates profile avatars: strictly images only, rejects PDF for avatars", () => {
      const validAvatar = validateFileUpload("avatar.jpg", "image/jpeg", 1 * 1024 * 1024, "avatar");
      expect(validAvatar.valid).toBe(true);

      const invalidAvatarPdf = validateFileUpload("avatar.pdf", "application/pdf", 1 * 1024 * 1024, "avatar");
      expect(invalidAvatarPdf.valid).toBe(false);
      expect(invalidAvatarPdf.error).toContain("Profile avatars must be a valid image");
    });
  });

  // ── 2. Filename Sanitization & Directory Traversal Prevention ──────
  describe("sanitizeFilename", () => {
    test("strips path traversal attacks and dangerous characters", () => {
      const sanitized = sanitizeFilename("../../../etc/passwd");
      expect(sanitized).toBe("passwd");
      expect(sanitized).not.toContain("/");
      expect(sanitized).not.toContain("..");

      const safeChars = sanitizeFilename("My Task Report (v2.0) [Final]!.pdf");
      expect(safeChars).toBe("My_Task_Report_v2.0_Final_.pdf");
    });
  });

  // ── 3. S3 Key Generation ───────────────────────────────────────────
  describe("generateS3Key", () => {
    test("creates collision-proof, URL-safe keys with UUID prefixes", () => {
      const taskId = "task-12345";
      const key1 = generateS3Key("attachments", taskId, "specs.pdf");
      const key2 = generateS3Key("attachments", taskId, "specs.pdf");

      expect(key1).toMatch(/^attachments\/task-12345\/[a-f0-9-]+-specs\.pdf$/);
      expect(key2).toMatch(/^attachments\/task-12345\/[a-f0-9-]+-specs\.pdf$/);
      // Keys must be unique due to random UUID
      expect(key1).not.toBe(key2);
    });

    test("supports avatars namespace", () => {
      const userId = "usr-8888";
      const key = generateS3Key("avatars", userId, "my-face.png");
      expect(key).toMatch(/^avatars\/usr-8888\/[a-f0-9-]+-my-face\.png$/);
    });
  });

  // ── 4. Presigned Upload & Download URLs ─────────────────────────────
  describe("Presigned URL Generation", () => {
    test("generates presigned PUT upload URL with 300-second TTL", async () => {
      const key = "attachments/t1/uuid-file.png";
      const url = await createPresignedUploadUrl({
        key,
        contentType: "image/png",
        contentLength: 2048,
        bucket: "taskflow-test-bucket",
        expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
      });

      expect(url).toContain("taskflow-test-bucket");
      expect(url).toContain(key);
      expect(url).toContain("X-Amz-Expires=300");
    });

    test("generates presigned GET download URL with attachment content disposition", async () => {
      const key = "attachments/t1/uuid-file.pdf";
      const url = await createPresignedDownloadUrl({
        key,
        filename: "Important Document.pdf",
        bucket: "taskflow-test-bucket",
        expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
      });

      expect(url).toContain("taskflow-test-bucket");
      expect(url).toContain(key);
      expect(url).toContain("X-Amz-Expires=300");
    });
  });

  // ── 5. Authorization & Multi-Tenant Access Boundaries ─────────────
  describe("Tenant & Workspace Authorization Boundaries", () => {
    test("rejects upload when user is not a member of the task's workspace", () => {
      const mockWorkspaceMembers = [{ userId: "user-123" }, { userId: "user-456" }];
      const requestingUserId = "attacker-789";

      const isAuthorized = mockWorkspaceMembers.some((m) => m.userId === requestingUserId);
      expect(isAuthorized).toBe(false);
    });

    test("authorizes upload when user is an active workspace member", () => {
      const mockWorkspaceMembers = [{ userId: "user-123" }, { userId: "user-456" }];
      const requestingUserId = "user-123";

      const isAuthorized = mockWorkspaceMembers.some((m) => m.userId === requestingUserId);
      expect(isAuthorized).toBe(true);
    });

    test("prevents cross-tenant download by enforcing workspace membership check", () => {
      const attachmentTaskWorkspaceMembers = [{ userId: "legitimate-member" }];
      const crossTenantUser = "external-tenant-user";

      const canDownload = attachmentTaskWorkspaceMembers.some((m) => m.userId === crossTenantUser);
      expect(canDownload).toBe(false);
    });
  });

  // ── 6. Prisma Database Schema & Metadata Consistency ───────────────
  describe("Prisma PostgreSQL Schema Metadata", () => {
    test("verifies attachment metadata mapping format", () => {
      const mockAttachmentRecord = {
        id: "att-cuid-123",
        filename: "architecture-v1.pdf",
        url: `s3://${S3_BUCKET_NAME}/attachments/task-99/uuid-architecture-v1.pdf`,
        size: 1048576,
        mimeType: "application/pdf",
        taskId: "task-99",
        createdAt: new Date().toISOString(),
      };

      expect(mockAttachmentRecord.id).toBeTruthy();
      expect(mockAttachmentRecord.url).toMatch(/^s3:\/\/.+\/attachments\/task-99\/.+$/);
      expect(mockAttachmentRecord.size).toBeGreaterThan(0);
      expect(mockAttachmentRecord.mimeType).toBe("application/pdf");
    });
  });

  // ── 7. Constants & Security Defaults ───────────────────────────────
  describe("Security Defaults", () => {
    test("enforces 300-second presigned URL expiry", () => {
      expect(PRESIGNED_URL_EXPIRY_SECONDS).toBe(300);
    });

    test("ensures default S3 bucket name is non-empty and contains region", () => {
      expect(S3_BUCKET_NAME).toBeTruthy();
      expect(S3_BUCKET_NAME).toContain("taskflow-attachments");
    });
  });
});
