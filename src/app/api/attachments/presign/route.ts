export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import { z } from "zod";
import { Role } from "@prisma/client";
import { getAuthenticatedUser } from "@/lib/auth-guard";
import prisma from "@/lib/prisma";
import {
  validateFileUpload,
  generateS3Key,
  createPresignedUploadUrl,
  S3_BUCKET_NAME,
  PRESIGNED_URL_EXPIRY_SECONDS,
} from "@/lib/s3";

const presignRequestSchema = z.object({
  taskId: z.string().min(1, "Task ID is required").max(128),
  filename: z.string().min(1, "Filename is required").max(255),
  fileType: z.string().min(1, "MIME type is required").max(128),
  fileSize: z.number().int().positive("File size must be greater than 0"),
});

export async function POST(req: Request) {
  try {
    // 1. Strictly authenticate user (no demo fallback)
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ error: "Unauthorized access" }, { status: 401 });
    }

    // 2. Validate request payload
    const body = await req.json().catch(() => null);
    const parsed = presignRequestSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.errors[0]?.message || "Invalid payload" },
        { status: 400 }
      );
    }

    const { taskId, filename, fileType, fileSize } = parsed.data;

    // 3. Verify task exists and verify user has write access via project workspace
    const task = await prisma.task.findUnique({
      where: { id: taskId },
      include: {
        project: {
          include: {
            workspace: {
              include: {
                members: { where: { userId: user.id } },
              },
            },
          },
        },
      },
    });

    if (!task) {
      return NextResponse.json({ error: "Target task not found" }, { status: 404 });
    }

    const membership = task.project.workspace.members[0];
    if (!membership || membership.role === Role.VIEWER) {
      return NextResponse.json(
        { error: "Forbidden: You do not have permission to attach files to this task" },
        { status: 403 }
      );
    }

    // 4. Validate file type, extension, and size limits (JPEG, PNG, WebP, PDF only; reject SVG & executables)
    const validation = validateFileUpload(filename, fileType, fileSize, "attachment");
    if (!validation.valid) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    // 5. Generate server-controlled, collision-proof S3 key scoped to taskId
    const sanitizedName = validation.sanitizedFilename || filename;
    const key = generateS3Key("attachments", taskId, sanitizedName);

    // 6. Generate 300-second short-lived presigned upload URL bound to contentType & contentLength
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
      filename: sanitizedName,
      fileType: fileType.trim().toLowerCase(),
      fileSize,
    });
  } catch (error) {
    console.error("[Presign Upload API Error]:", error);
    return NextResponse.json(
      { error: "Internal server error generating presigned upload URL" },
      { status: 500 }
    );
  }
}
