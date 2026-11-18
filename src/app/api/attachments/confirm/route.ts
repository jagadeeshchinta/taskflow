export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import { z } from "zod";
import { AuditAction, Role } from "@prisma/client";
import { getAuthenticatedUser } from "@/lib/auth-guard";
import prisma from "@/lib/prisma";
import {
  S3_BUCKET_NAME,
  validateFileUpload,
  validateS3ObjectKey,
  verifyUploadedS3Object,
} from "@/lib/s3";

const confirmAttachmentSchema = z.object({
  taskId: z.string().min(1, "Task ID is required").max(128),
  key: z.string().min(1, "Object key is required").max(512),
  filename: z.string().min(1, "Filename is required").max(255),
  size: z.number().int().positive("Size must be positive"),
  mimeType: z.string().min(1, "MIME type is required").max(128),
});

export async function POST(req: Request) {
  try {
    // 1. Strictly authenticate user (no demo fallback)
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ error: "Unauthorized access" }, { status: 401 });
    }

    const body = await req.json().catch(() => null);
    const parsed = confirmAttachmentSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.errors[0]?.message || "Invalid payload" },
        { status: 400 }
      );
    }

    const { taskId, key, filename, size, mimeType } = parsed.data;

    // 2. Verify task exists and user belongs to workspace with write access
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

    // 3. Enforce strict server-generated key scope (prevents cross-task/cross-workspace key hijacking)
    if (!validateS3ObjectKey(key, "attachments", taskId)) {
      return NextResponse.json(
        { error: "Forbidden: Object key does not match the authorized task scope" },
        { status: 403 }
      );
    }

    // 4. Re-validate filename, extension, declared MIME type, and declared size
    const validation = validateFileUpload(filename, mimeType, size, "attachment");
    if (!validation.valid) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    // 5. Server-side S3 verification: check actual ContentLength via HeadObject and verify magic bytes.
    //    Automatically deletes oversized, forged-MIME, SVG, or executable objects from S3.
    const s3Verification = await verifyUploadedS3Object({
      key,
      expectedMimeType: mimeType,
      purpose: "attachment",
      bucket: S3_BUCKET_NAME,
    });

    if (!s3Verification.valid || !s3Verification.actualSize || !s3Verification.detectedMimeType) {
      return NextResponse.json(
        { error: s3Verification.error || "Uploaded file failed server-side security verification" },
        { status: 400 }
      );
    }

    const safeFilename = validation.sanitizedFilename || filename;

    // 6. Persist verified metadata (using ACTUAL S3 size & detected MIME type, never browser claims)
    const attachment = await prisma.attachment.create({
      data: {
        taskId,
        filename: safeFilename,
        size: s3Verification.actualSize,
        mimeType: s3Verification.detectedMimeType,
        url: `s3://${S3_BUCKET_NAME}/${key}`,
      },
    });

    // Record audit log
    await prisma.auditLog
      .create({
        data: {
          action: AuditAction.UPDATE,
          entityType: "TASK",
          entityId: taskId,
          userId: user.id,
          details: {
            event: "ATTACHMENT_ADDED",
            attachmentId: attachment.id,
            filename: safeFilename,
            size: s3Verification.actualSize,
            mimeType: s3Verification.detectedMimeType,
            s3Key: key,
          },
        },
      })
      .catch(() => null);

    return NextResponse.json(
      {
        message: "Attachment confirmed and saved successfully",
        attachment: {
          id: attachment.id,
          filename: attachment.filename,
          size: attachment.size,
          mimeType: attachment.mimeType,
          taskId: attachment.taskId,
          createdAt: attachment.createdAt.toISOString(),
          s3Key: key,
        },
      },
      { status: 201 }
    );
  } catch (error) {
    console.error("[Confirm Attachment Error]:", error);
    return NextResponse.json(
      { error: "Internal server error confirming attachment" },
      { status: 500 }
    );
  }
}
