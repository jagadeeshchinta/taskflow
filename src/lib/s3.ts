// ═══════════════════════════════════════════════════════════════
//  TASKFLOW — AWS S3 Client & Secure Presigned URL Service
//  Enforces strict MIME + magic-byte validation, HeadObject size
//  verification, scoped object keys, 300s TTL, and IAM roles.
// ═══════════════════════════════════════════════════════════════

import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import crypto from "crypto";
import path from "path";

// ── Environment Configuration ─────────────────────────────────
const region = process.env.AWS_REGION || "ap-south-1";
export const S3_BUCKET_NAME =
  process.env.S3_ATTACHMENTS_BUCKET || "taskflow-attachments-local";

export function isMockS3Enabled(): boolean {
  return process.env.MOCK_S3 === "true" && process.env.NODE_ENV !== "production";
}

// ── S3 Client Singleton (Uses AWS IAM Instance Profile or Local Env) ──
const globalForS3 = globalThis as unknown as {
  s3Client: S3Client | undefined;
  mockS3Store: Map<string, { body: Buffer; contentType: string; createdAt: number }> | undefined;
};

export const s3Client =
  globalForS3.s3Client ??
  new S3Client({
    region,
    // When deployed on EC2 with an IAM Instance Profile, credentials
    // are automatically resolved via AWS default credential provider chain.
  });

if (process.env.NODE_ENV !== "production") {
  globalForS3.s3Client = s3Client;
}

// Dev/test-only in-memory mock S3 store (never active in production)
const mockStore =
  globalForS3.mockS3Store ??
  new Map<string, { body: Buffer; contentType: string; createdAt: number }>();

if (process.env.NODE_ENV !== "production") {
  globalForS3.mockS3Store = mockStore;
}

export function putMockS3Object(key: string, body: Buffer, contentType: string): void {
  if (!isMockS3Enabled()) {
    throw new Error("Mock S3 is disabled");
  }
  mockStore.set(key, { body, contentType, createdAt: Date.now() });
}

export function getMockS3Object(key: string) {
  if (!isMockS3Enabled()) return undefined;
  return mockStore.get(key);
}

export function clearMockS3Store(): void {
  mockStore.clear();
}

// ── Security Constraints & Validation Constants ───────────────
export const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
export const MAX_DOCUMENT_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
export const PRESIGNED_URL_EXPIRY_SECONDS = 300; // 5 Minutes TTL

export const ALLOWED_IMAGE_MIME_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
] as const;

export const ALLOWED_DOCUMENT_MIME_TYPES = [
  "application/pdf",
] as const;

export const ALLOWED_ALL_MIME_TYPES = [
  ...ALLOWED_IMAGE_MIME_TYPES,
  ...ALLOWED_DOCUMENT_MIME_TYPES,
] as const;

export const STRICTLY_FORBIDDEN_EXTENSIONS = [
  ".svg",
  ".svgz",
  ".exe",
  ".dll",
  ".com",
  ".scr",
  ".pif",
  ".sh",
  ".bash",
  ".bat",
  ".cmd",
  ".vbs",
  ".js",
  ".mjs",
  ".cjs",
  ".msi",
  ".jar",
  ".ps1",
  ".php",
  ".py",
  ".pl",
  ".rb",
  ".html",
  ".htm",
  ".xhtml",
  ".xml",
];

export interface FileValidationResult {
  valid: boolean;
  error?: string;
  sanitizedFilename?: string;
  category?: "image" | "document";
  maxSizeBytes?: number;
}

export interface MagicByteCheckResult {
  detectedMime: string | null;
  rejectedReason?: string;
}

export interface UploadedObjectVerificationResult {
  valid: boolean;
  error?: string;
  actualSize?: number;
  detectedMimeType?: string;
}

/**
 * Returns the maximum allowed file size for a given MIME type and upload purpose.
 */
export function getMaxSizeForMimeType(
  mimeType: string,
  purpose: "attachment" | "avatar" = "attachment"
): number {
  const normalized = mimeType.trim().toLowerCase();
  if (purpose === "avatar") {
    return MAX_IMAGE_SIZE_BYTES;
  }
  if ((ALLOWED_IMAGE_MIME_TYPES as readonly string[]).includes(normalized)) {
    return MAX_IMAGE_SIZE_BYTES;
  }
  if ((ALLOWED_DOCUMENT_MIME_TYPES as readonly string[]).includes(normalized)) {
    return MAX_DOCUMENT_SIZE_BYTES;
  }
  return 0;
}

/**
 * Validates file upload parameters against strict DevSecOps whitelist rules.
 * Strictly rejects SVG, executable/script files, null bytes, and files exceeding size limits.
 */
export function validateFileUpload(
  filename: string,
  mimeType: string,
  fileSize: number,
  purpose: "attachment" | "avatar" = "attachment"
): FileValidationResult {
  if (!filename || typeof filename !== "string") {
    return { valid: false, error: "Filename is required" };
  }

  if (filename.includes("\0") || /[\r\n]/.test(filename)) {
    return { valid: false, error: "Filename contains illegal control characters" };
  }

  if (typeof fileSize !== "number" || !Number.isFinite(fileSize) || !Number.isInteger(fileSize) || fileSize <= 0) {
    return { valid: false, error: "File size must be a positive integer" };
  }

  const baseName = path.basename(filename);
  const ext = path.extname(baseName).toLowerCase();
  if (!ext) {
    return { valid: false, error: "File must have a valid extension" };
  }

  // 1. Strictly reject forbidden extensions (prevent SVG XSS and executable malware)
  if (STRICTLY_FORBIDDEN_EXTENSIONS.includes(ext)) {
    return {
      valid: false,
      error: `File extension '${ext}' is strictly prohibited for security reasons`,
    };
  }

  // Also reject suspicious double extensions ending with dangerous inner tokens like .php.jpg or .svg.png
  const nameTokens = baseName.toLowerCase().split(".").slice(1);
  for (const token of nameTokens) {
    if (STRICTLY_FORBIDDEN_EXTENSIONS.includes(`.${token}`)) {
      return {
        valid: false,
        error: `Filename contains strictly prohibited extension '.${token}'`,
      };
    }
  }

  // 2. Validate MIME type against purpose
  const normalizedMime = (mimeType || "").trim().toLowerCase();

  if (purpose === "avatar") {
    if (!(ALLOWED_IMAGE_MIME_TYPES as readonly string[]).includes(normalizedMime)) {
      return {
        valid: false,
        error: "Profile avatars must be a valid image (JPEG, PNG, or WebP)",
      };
    }
    if (fileSize > MAX_IMAGE_SIZE_BYTES) {
      return {
        valid: false,
        error: `Avatar file size (${(fileSize / (1024 * 1024)).toFixed(1)}MB) exceeds maximum limit of 5MB`,
      };
    }
    if (
      (normalizedMime === "image/jpeg" && ![".jpg", ".jpeg"].includes(ext)) ||
      (normalizedMime === "image/png" && ext !== ".png") ||
      (normalizedMime === "image/webp" && ext !== ".webp")
    ) {
      return {
        valid: false,
        error: `File extension '${ext}' does not match MIME type '${normalizedMime}'`,
      };
    }

    return {
      valid: true,
      category: "image",
      maxSizeBytes: MAX_IMAGE_SIZE_BYTES,
      sanitizedFilename: sanitizeFilename(filename),
    };
  }

  // Attachment validation (images + PDF)
  const isImage = (ALLOWED_IMAGE_MIME_TYPES as readonly string[]).includes(normalizedMime);
  const isPdf = (ALLOWED_DOCUMENT_MIME_TYPES as readonly string[]).includes(normalizedMime);

  if (!isImage && !isPdf) {
    return {
      valid: false,
      error: `Unsupported file type '${normalizedMime}'. Allowed types: JPEG, PNG, WebP, PDF`,
    };
  }

  // Extension matching validation
  if (isPdf && ext !== ".pdf") {
    return {
      valid: false,
      error: "PDF documents must have a .pdf file extension",
    };
  }
  if (
    isImage &&
    ((normalizedMime === "image/jpeg" && ![".jpg", ".jpeg"].includes(ext)) ||
      (normalizedMime === "image/png" && ext !== ".png") ||
      (normalizedMime === "image/webp" && ext !== ".webp"))
  ) {
    return {
      valid: false,
      error: `File extension '${ext}' does not match MIME type '${normalizedMime}'`,
    };
  }

  // Size limit validation
  if (isImage && fileSize > MAX_IMAGE_SIZE_BYTES) {
    return {
      valid: false,
      error: `Image file size (${(fileSize / (1024 * 1024)).toFixed(1)}MB) exceeds maximum limit of 5MB`,
    };
  }
  if (isPdf && fileSize > MAX_DOCUMENT_SIZE_BYTES) {
    return {
      valid: false,
      error: `Document file size (${(fileSize / (1024 * 1024)).toFixed(1)}MB) exceeds maximum limit of 10MB`,
    };
  }

  return {
    valid: true,
    category: isImage ? "image" : "document",
    maxSizeBytes: isImage ? MAX_IMAGE_SIZE_BYTES : MAX_DOCUMENT_SIZE_BYTES,
    sanitizedFilename: sanitizeFilename(filename),
  };
}

/**
 * Inspects actual file header bytes (magic numbers) to verify true content type
 * and reject forged MIME types, SVG/HTML/XML, and executable binaries.
 */
export function detectMimeTypeFromMagicBytes(
  data: Uint8Array | Buffer
): MagicByteCheckResult {
  if (!data || data.length < 4) {
    return { detectedMime: null, rejectedReason: "File content is empty or too short to verify" };
  }

  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

  // Explicit active-content / executable rejection checks
  // Windows PE executable ("MZ")
  if (buf[0] === 0x4d && buf[1] === 0x5a) {
    return { detectedMime: null, rejectedReason: "Executable binary (PE/MZ) content is strictly prohibited" };
  }
  // Linux ELF executable ("\x7fELF")
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    return { detectedMime: null, rejectedReason: "Executable binary (ELF) content is strictly prohibited" };
  }
  // Shell script shebang ("#!")
  if (buf[0] === 0x23 && buf[1] === 0x21) {
    return { detectedMime: null, rejectedReason: "Script file content (#!) is strictly prohibited" };
  }
  // SVG / XML / HTML text payload check (trim BOM & leading whitespace)
  const asciiPrefix = buf
    .subarray(0, Math.min(buf.length, 64))
    .toString("utf8")
    .replace(/^\uFEFF/, "")
    .trimStart()
    .toLowerCase();

  if (
    asciiPrefix.startsWith("<svg") ||
    asciiPrefix.startsWith("<?xml") ||
    asciiPrefix.startsWith("<!doctype html") ||
    asciiPrefix.startsWith("<html") ||
    asciiPrefix.startsWith("<script")
  ) {
    return {
      detectedMime: null,
      rejectedReason: "SVG, XML, HTML, or script content is strictly prohibited",
    };
  }

  // Valid JPEG: FF D8 FF
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { detectedMime: "image/jpeg" };
  }

  // Valid PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buf.length >= 8 &&
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
  ) {
    return { detectedMime: "image/png" };
  }

  // Valid WebP: "RIFF" (0..3) + "WEBP" (8..11)
  if (
    buf.length >= 12 &&
    buf[0] === 0x52 &&
    buf[1] === 0x49 &&
    buf[2] === 0x46 &&
    buf[3] === 0x46 &&
    buf[8] === 0x57 &&
    buf[9] === 0x45 &&
    buf[10] === 0x42 &&
    buf[11] === 0x50
  ) {
    return { detectedMime: "image/webp" };
  }

  // Valid PDF: "%PDF-"
  if (
    buf.length >= 5 &&
    buf[0] === 0x25 &&
    buf[1] === 0x50 &&
    buf[2] === 0x44 &&
    buf[3] === 0x46 &&
    buf[4] === 0x2d
  ) {
    return { detectedMime: "application/pdf" };
  }

  return {
    detectedMime: null,
    rejectedReason: "File content signature does not match an allowed format (JPEG, PNG, WebP, or PDF)",
  };
}

/**
 * Sanitizes filename to prevent directory traversal and special character exploits.
 */
export function sanitizeFilename(filename: string): string {
  const base = path.basename(filename);
  return base
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .replace(/_{2,}/g, "_")
    .replace(/^\.+/, "_")
    .slice(0, 100);
}

/**
 * Generates a collision-proof S3 object key strictly scoped to entityId.
 */
export function generateS3Key(
  prefix: "attachments" | "avatars",
  entityId: string,
  filename: string
): string {
  if (!entityId || !/^[a-zA-Z0-9_-]+$/.test(entityId)) {
    throw new Error("Invalid entity identifier for S3 key");
  }
  const safeFilename = sanitizeFilename(filename);
  const uniqueId = crypto.randomUUID();
  return `${prefix}/${entityId}/${uniqueId}-${safeFilename}`;
}

/**
 * Validates that a client-supplied S3 object key strictly matches the server-generated
 * prefix, entity ownership scope, UUID format, and contains zero path traversal characters.
 */
export function validateS3ObjectKey(
  key: string,
  expectedPrefix: "attachments" | "avatars",
  expectedEntityId: string
): boolean {
  if (!key || typeof key !== "string") return false;
  if (
    key.includes("..") ||
    key.includes("\\") ||
    key.includes("\0") ||
    key.startsWith("/") ||
    key.includes("://")
  ) {
    return false;
  }

  const escapedEntityId = expectedEntityId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `^${expectedPrefix}/${escapedEntityId}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[a-zA-Z0-9._-]+$`,
    "i"
  );
  return pattern.test(key);
}

/**
 * Extracts raw S3 key from stored attachment URL ("s3://bucket/key" or raw "key").
 */
export function extractS3KeyFromUrl(url: string): string {
  if (url.startsWith("s3://")) {
    const parts = url.replace("s3://", "").split("/");
    parts.shift(); // remove bucket name
    return parts.join("/");
  }
  return url;
}

/**
 * Reads a byte range from an S3 object body stream into a Buffer.
 */
async function readBodyToBuffer(body: unknown): Promise<Buffer> {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (typeof (body as { transformToByteArray?: () => Promise<Uint8Array> }).transformToByteArray === "function") {
    const arr = await (body as { transformToByteArray: () => Promise<Uint8Array> }).transformToByteArray();
    return Buffer.from(arr);
  }
  // Node.js ReadableStream fallback
  const chunks: Buffer[] = [];
  for await (const chunk of body as AsyncIterable<Uint8Array | string>) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/**
 * Verifies an already-uploaded S3 object on the server BEFORE confirming it in PostgreSQL:
 * 1. Fetches actual ContentLength via HeadObjectCommand (never trusts browser-claimed size).
 * 2. Fetches first 64 bytes via GetObjectCommand (Range: bytes=0-63) and verifies magic bytes.
 * 3. Rejects & automatically deletes oversized, forged-MIME, SVG, or executable objects from S3.
 */
export async function verifyUploadedS3Object(params: {
  key: string;
  expectedMimeType: string;
  purpose: "attachment" | "avatar";
  bucket?: string;
}): Promise<UploadedObjectVerificationResult> {
  const {
    key,
    expectedMimeType,
    purpose,
    bucket = S3_BUCKET_NAME,
  } = params;

  const normalizedExpectedMime = expectedMimeType.trim().toLowerCase();
  const maxAllowedBytes = getMaxSizeForMimeType(normalizedExpectedMime, purpose);

  if (maxAllowedBytes <= 0) {
    return {
      valid: false,
      error: `Unsupported MIME type '${normalizedExpectedMime}' for ${purpose}`,
    };
  }

  let actualSize = 0;
  let headerBytes: Buffer;

  try {
    if (isMockS3Enabled()) {
      const mockObj = mockStore.get(key);
      if (!mockObj) {
        return { valid: false, error: "Uploaded object not found in storage" };
      }
      actualSize = mockObj.body.length;
      headerBytes = mockObj.body.subarray(0, Math.min(mockObj.body.length, 64));
    } else {
      // 1. HeadObject to get true S3 ContentLength
      const headResp = await s3Client.send(
        new HeadObjectCommand({
          Bucket: bucket,
          Key: key,
        })
      );
      actualSize = Number(headResp.ContentLength ?? 0);

      if (actualSize <= 0 || actualSize > maxAllowedBytes) {
        await deleteS3Object(key, bucket).catch(() => null);
        return {
          valid: false,
          actualSize,
          error:
            actualSize <= 0
              ? "Uploaded object is empty"
              : `Actual uploaded file size (${(actualSize / (1024 * 1024)).toFixed(2)}MB) exceeds maximum limit of ${(maxAllowedBytes / (1024 * 1024)).toFixed(0)}MB`,
        };
      }

      // 2. Partial GetObject (first 64 bytes) for magic-byte signature verification
      const getResp = await s3Client.send(
        new GetObjectCommand({
          Bucket: bucket,
          Key: key,
          Range: "bytes=0-63",
        })
      );
      headerBytes = await readBodyToBuffer(getResp.Body);
    }
  } catch (err: unknown) {
    const code = (err as { name?: string; $metadata?: { httpStatusCode?: number } })?.name;
    const status = (err as { $metadata?: { httpStatusCode?: number } })?.$metadata?.httpStatusCode;
    if (code === "NotFound" || code === "NoSuchKey" || status === 404) {
      return { valid: false, error: "Uploaded object does not exist in S3" };
    }
    throw err;
  }

  // Enforce actual size limit (also catches mockS3 oversized files)
  if (actualSize <= 0 || actualSize > maxAllowedBytes) {
    await deleteS3Object(key, bucket).catch(() => null);
    return {
      valid: false,
      actualSize,
      error:
        actualSize <= 0
          ? "Uploaded object is empty"
          : `Actual uploaded file size (${(actualSize / (1024 * 1024)).toFixed(2)}MB) exceeds maximum limit of ${(maxAllowedBytes / (1024 * 1024)).toFixed(0)}MB`,
    };
  }

  // Verify actual content magic bytes
  const magicCheck = detectMimeTypeFromMagicBytes(headerBytes);
  if (!magicCheck.detectedMime) {
    await deleteS3Object(key, bucket).catch(() => null);
    return {
      valid: false,
      actualSize,
      error: magicCheck.rejectedReason || "Uploaded file content failed signature verification",
    };
  }

  // Ensure detected MIME matches allowed category for purpose
  const detectedMaxSize = getMaxSizeForMimeType(magicCheck.detectedMime, purpose);
  if (detectedMaxSize <= 0 || actualSize > detectedMaxSize) {
    await deleteS3Object(key, bucket).catch(() => null);
    return {
      valid: false,
      actualSize,
      detectedMimeType: magicCheck.detectedMime,
      error: `Detected file content type '${magicCheck.detectedMime}' is not allowed or exceeds size limit for ${purpose}`,
    };
  }

  // Ensure declared MIME type was not forged
  if (magicCheck.detectedMime !== normalizedExpectedMime) {
    await deleteS3Object(key, bucket).catch(() => null);
    return {
      valid: false,
      actualSize,
      detectedMimeType: magicCheck.detectedMime,
      error: `MIME type mismatch: declared '${normalizedExpectedMime}' does not match actual content '${magicCheck.detectedMime}'`,
    };
  }

  return {
    valid: true,
    actualSize,
    detectedMimeType: magicCheck.detectedMime,
  };
}

/**
 * Defense-in-depth check before issuing a presigned download URL:
 * ensures the stored S3 object still respects size boundaries and valid key scope.
 */
export async function verifyS3ObjectForDownload(params: {
  key: string;
  taskId: string;
  mimeType: string;
  recordedSize: number;
  bucket?: string;
}): Promise<{ valid: boolean; error?: string; actualSize?: number }> {
  const { key, taskId, mimeType, recordedSize, bucket = S3_BUCKET_NAME } = params;

  if (!validateS3ObjectKey(key, "attachments", taskId)) {
    return { valid: false, error: "Invalid attachment storage key scope" };
  }

  const maxAllowedBytes = getMaxSizeForMimeType(mimeType, "attachment");
  if (maxAllowedBytes <= 0) {
    return { valid: false, error: "Attachment has disallowed MIME type" };
  }

  if (recordedSize <= 0 || recordedSize > maxAllowedBytes) {
    return { valid: false, error: "Attachment exceeds permitted download size limit" };
  }

  try {
    let actualSize = recordedSize;
    if (isMockS3Enabled()) {
      const mockObj = mockStore.get(key);
      if (!mockObj) {
        return { valid: false, error: "Attachment file not found in storage" };
      }
      actualSize = mockObj.body.length;
    } else {
      const headResp = await s3Client.send(
        new HeadObjectCommand({
          Bucket: bucket,
          Key: key,
        })
      );
      actualSize = Number(headResp.ContentLength ?? 0);
    }

    if (actualSize <= 0 || actualSize > maxAllowedBytes) {
      return {
        valid: false,
        actualSize,
        error: "Stored S3 object exceeds permitted size limit and cannot be downloaded",
      };
    }

    return { valid: true, actualSize };
  } catch (err: unknown) {
    const code = (err as { name?: string; $metadata?: { httpStatusCode?: number } })?.name;
    const status = (err as { $metadata?: { httpStatusCode?: number } })?.$metadata?.httpStatusCode;
    if (code === "NotFound" || code === "NoSuchKey" || status === 404) {
      return { valid: false, error: "Attachment file does not exist in storage" };
    }
    throw err;
  }
}

/**
 * Generates a short-lived presigned PUT URL for direct-to-S3 client uploads.
 * Expiry is strictly capped at PRESIGNED_URL_EXPIRY_SECONDS (300s).
 */
export async function createPresignedUploadUrl(params: {
  key: string;
  contentType: string;
  contentLength: number;
  bucket?: string;
  expiresIn?: number;
}): Promise<string> {
  const {
    key,
    contentType,
    contentLength,
    bucket = S3_BUCKET_NAME,
    expiresIn = PRESIGNED_URL_EXPIRY_SECONDS,
  } = params;

  const safeExpiresIn = Math.min(Math.max(1, expiresIn), PRESIGNED_URL_EXPIRY_SECONDS);

  if (isMockS3Enabled()) {
    const appUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
    return `${appUrl}/api/mock-s3?key=${encodeURIComponent(key)}&contentType=${encodeURIComponent(contentType)}`;
  }

  const command = new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    ContentType: contentType,
    ContentLength: contentLength,
  });

  return getSignedUrl(s3Client, command, { expiresIn: safeExpiresIn });
}

/**
 * Generates a short-lived presigned GET URL for secure attachment downloads.
 * Enforces Content-Disposition: attachment and caps expiry at 300s.
 */
export async function createPresignedDownloadUrl(params: {
  key: string;
  filename: string;
  bucket?: string;
  expiresIn?: number;
}): Promise<string> {
  const {
    key,
    filename,
    bucket = S3_BUCKET_NAME,
    expiresIn = PRESIGNED_URL_EXPIRY_SECONDS,
  } = params;

  const safeExpiresIn = Math.min(Math.max(1, expiresIn), PRESIGNED_URL_EXPIRY_SECONDS);
  const safeDispositionName = sanitizeFilename(filename);

  if (isMockS3Enabled()) {
    const appUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
    return `${appUrl}/api/mock-s3?key=${encodeURIComponent(key)}&filename=${encodeURIComponent(safeDispositionName)}`;
  }

  const command = new GetObjectCommand({
    Bucket: bucket,
    Key: key,
    ResponseContentDisposition: `attachment; filename="${safeDispositionName}"; filename*=UTF-8''${encodeURIComponent(safeDispositionName)}`,
  });

  return getSignedUrl(s3Client, command, { expiresIn: safeExpiresIn });
}

/**
 * Deletes an object from S3 (or mock store in dev/test).
 */
export async function deleteS3Object(key: string, bucket: string = S3_BUCKET_NAME): Promise<void> {
  if (isMockS3Enabled()) {
    mockStore.delete(key);
    return;
  }

  const command = new DeleteObjectCommand({
    Bucket: bucket,
    Key: key,
  });

  await s3Client.send(command);
}
