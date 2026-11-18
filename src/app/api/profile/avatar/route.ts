export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import { z } from "zod";
import { getAuthenticatedUser } from "@/lib/auth-guard";
import prisma from "@/lib/prisma";
import {
  validateFileUpload,
  validateS3ObjectKey,
  verifyUploadedS3Object,
  generateS3Key,
  createPresignedUploadUrl,
  S3_BUCKET_NAME,
  PRESIGNED_URL_EXPIRY_SECONDS,
} from "@/lib/s3";

const avatarPresignSchema = z.object({
  filename: z.string().min(1, "Filename is required").max(255),
  fileType: z.string().min(1, "MIME type is required").max(128),
  fileSize: z.number().int().positive("File size must be positive"),
});

const avatarConfirmSchema = z.object({
  key: z.string().min(1, "S3 key is required").max(512),
  fileType: z.string().min(1, "MIME type is required").max(128).optional(),
});

// POST: Generate presigned upload URL for authenticated user's own avatar
export async function POST(req: Request) {
  try {
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ error: "Unauthorized access" }, { status: 401 });
    }

    const body = await req.json().catch(() => null);
    const parsed = avatarPresignSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.errors[0]?.message || "Invalid payload" },
        { status: 400 }
      );
    }

    const { filename, fileType, fileSize } = parsed.data;

    // Validate avatar: strictly JPEG, PNG, WebP only, max 5MB, reject SVG & executables
    const validation = validateFileUpload(filename, fileType, fileSize, "avatar");
    if (!validation.valid) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    // Generate server-controlled unique key strictly scoped to authenticated user.id
    const safeFilename = validation.sanitizedFilename || filename;
    const key = generateS3Key("avatars", user.id, safeFilename);

    const uploadUrl = await createPresignedUploadUrl({
      key,
      contentType: fileType.trim().toLowerCase(),
      contentLength: fileSize,
      bucket: S3_BUCKET_NAME,
      expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
    });

    return NextResponse.json({
      uploadUrl,
      key,
      bucket: S3_BUCKET_NAME,
      expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
      filename: safeFilename,
      fileType: fileType.trim().toLowerCase(),
    });
  } catch (error) {
    console.error("[Avatar Presign Error]:", error);
    return NextResponse.json(
      { error: "Internal server error generating avatar upload URL" },
      { status: 500 }
    );
  }
}

// PUT: Verify uploaded avatar object in S3 and update ONLY the authenticated user's own profile
export async function PUT(req: Request) {
  try {
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ error: "Unauthorized access" }, { status: 401 });
    }

    const body = await req.json().catch(() => null);
    const parsed = avatarConfirmSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.errors[0]?.message || "Invalid payload" },
        { status: 400 }
      );
    }

    const { key, fileType } = parsed.data;

    // 1. Enforce strict ownership: key MUST belong to avatars/<authenticated-user-id>/<uuid>-<file>
    if (!validateS3ObjectKey(key, "avatars", user.id)) {
      return NextResponse.json(
        { error: "Forbidden: Avatar object key does not belong to the authenticated user" },
        { status: 403 }
      );
    }

    // Derive expected MIME type from key extension if fileType not explicitly sent
    const ext = key.split(".").pop()?.toLowerCase();
    const inferredMime =
      fileType?.trim().toLowerCase() ||
      (ext === "jpg" || ext === "jpeg"
        ? "image/jpeg"
        : ext === "png"
        ? "image/png"
        : ext === "webp"
        ? "image/webp"
        : "");

    // 2. Verify actual S3 object exists, size <= 5MB, and magic bytes match JPEG/PNG/WebP
    const s3Verification = await verifyUploadedS3Object({
      key,
      expectedMimeType: inferredMime,
      purpose: "avatar",
      bucket: S3_BUCKET_NAME,
    });

    if (!s3Verification.valid) {
      return NextResponse.json(
        { error: s3Verification.error || "Uploaded avatar failed security verification" },
        { status: 400 }
      );
    }

    const avatarUrl = `s3://${S3_BUCKET_NAME}/${key}`;

    // 3. Strictly update ONLY the authenticated user's record (userId from body is ignored)
    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: { image: avatarUrl },
      select: { id: true, name: true, email: true, image: true, updatedAt: true },
    });

    return NextResponse.json({
      message: "Avatar updated successfully",
      user: updatedUser,
      avatarKey: key,
      size: s3Verification.actualSize,
      mimeType: s3Verification.detectedMimeType,
    });
  } catch (error) {
    console.error("[Avatar Confirm Error]:", error);
    return NextResponse.json(
      { error: "Internal server error updating avatar" },
      { status: 500 }
    );
  }
}
