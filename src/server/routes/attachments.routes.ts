// ═══════════════════════════════════════════════════════════════
//  TASKFLOW — Express Attachments & Avatar Routes (AWS S3 & PostgreSQL)
//  Enforces strict parity with Next.js API security & RBAC controls
// ═══════════════════════════════════════════════════════════════

import { Router, Response, NextFunction } from "express";
import { AuditAction, Role } from "@prisma/client";
import { authMiddleware, AuthRequest } from "../middleware/auth.middleware";
import prisma from "../../lib/prisma";
import {
  validateFileUpload,
  validateS3ObjectKey,
  verifyUploadedS3Object,
  verifyS3ObjectForDownload,
  extractS3KeyFromUrl,
  generateS3Key,
  createPresignedUploadUrl,
  createPresignedDownloadUrl,
  S3_BUCKET_NAME,
  PRESIGNED_URL_EXPIRY_SECONDS,
} from "../../lib/s3";
import { z } from "zod";

const router = Router();
router.use(authMiddleware);

const presignSchema = z.object({
  taskId: z.string().min(1).max(128),
  filename: z.string().min(1).max(255),
  fileType: z.string().min(1).max(128),
  fileSize: z.number().int().positive(),
});

const confirmSchema = z.object({
  taskId: z.string().min(1).max(128),
  key: z.string().min(1).max(512),
  filename: z.string().min(1).max(255),
  size: z.number().int().positive(),
  mimeType: z.string().min(1).max(128),
});

const avatarPresignSchema = z.object({
  filename: z.string().min(1).max(255),
  fileType: z.string().min(1).max(128),
  fileSize: z.number().int().positive(),
});

const avatarConfirmSchema = z.object({
  key: z.string().min(1).max(512),
  fileType: z.string().min(1).max(128).optional(),
});

// POST /api/v1/attachments/presign — Generate presigned PUT URL
router.post("/presign", async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const parsed = presignSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid payload",
      });
    }

    const { taskId, filename, fileType, fileSize } = parsed.data;

    const task = await prisma.task.findUnique({
      where: { id: taskId },
      include: {
        project: {
          include: {
            workspace: {
              include: {
                members: { where: { userId: req.userId! } },
              },
            },
          },
        },
      },
    });

    if (!task) {
      return res.status(404).json({ success: false, error: "Task not found" });
    }

    const membership = task.project.workspace.members[0];
    if (!membership || membership.role === Role.VIEWER) {
      return res.status(403).json({
        success: false,
        error: "Forbidden: You do not have permission to attach files to this task",
      });
    }

    const validation = validateFileUpload(filename, fileType, fileSize, "attachment");
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    const safeFilename = validation.sanitizedFilename || filename;
    const key = generateS3Key("attachments", taskId, safeFilename);
    const uploadUrl = await createPresignedUploadUrl({
      key,
      contentType: fileType.trim().toLowerCase(),
      contentLength: fileSize,
      bucket: S3_BUCKET_NAME,
      expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
    });

    res.json({
      success: true,
      data: {
        uploadUrl,
        key,
        bucket: S3_BUCKET_NAME,
        expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
        filename: safeFilename,
      },
    });
  } catch (error) {
    next(error);
  }
});

// POST /api/v1/attachments/confirm — Verify S3 object (actual size + magic bytes) & persist metadata
router.post("/confirm", async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const parsed = confirmSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid payload",
      });
    }

    const { taskId, key, filename, size, mimeType } = parsed.data;

    const task = await prisma.task.findUnique({
      where: { id: taskId },
      include: {
        project: {
          include: {
            workspace: {
              include: {
                members: { where: { userId: req.userId! } },
              },
            },
          },
        },
      },
    });

    if (!task) {
      return res.status(404).json({ success: false, error: "Task not found" });
    }

    const membership = task.project.workspace.members[0];
    if (!membership || membership.role === Role.VIEWER) {
      return res.status(403).json({
        success: false,
        error: "Forbidden: You do not have permission to attach files to this task",
      });
    }

    // Strictly verify key scope to prevent cross-task/cross-workspace key hijacking
    if (!validateS3ObjectKey(key, "attachments", taskId)) {
      return res.status(403).json({
        success: false,
        error: "Forbidden: Object key does not match the authorized task scope",
      });
    }

    // Re-validate filename, extension, MIME, and declared size
    const validation = validateFileUpload(filename, mimeType, size, "attachment");
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    // Verify ACTUAL S3 object ContentLength and magic-byte signature (deletes invalid objects)
    const s3Verification = await verifyUploadedS3Object({
      key,
      expectedMimeType: mimeType,
      purpose: "attachment",
      bucket: S3_BUCKET_NAME,
    });

    if (!s3Verification.valid || !s3Verification.actualSize || !s3Verification.detectedMimeType) {
      return res.status(400).json({
        success: false,
        error: s3Verification.error || "Uploaded file failed server-side security verification",
      });
    }

    const safeFilename = validation.sanitizedFilename || filename;

    const attachment = await prisma.attachment.create({
      data: {
        taskId,
        filename: safeFilename,
        size: s3Verification.actualSize,
        mimeType: s3Verification.detectedMimeType,
        url: `s3://${S3_BUCKET_NAME}/${key}`,
      },
    });

    await prisma.auditLog
      .create({
        data: {
          action: AuditAction.UPDATE,
          entityType: "TASK",
          entityId: taskId,
          userId: req.userId!,
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

    res.status(201).json({ success: true, data: attachment });
  } catch (error) {
    next(error);
  }
});

// GET /api/v1/attachments/task/:taskId — List task attachments (workspace members only)
router.get("/task/:taskId", async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const taskId = String(req.params.taskId);
    const task = await prisma.task.findUnique({
      where: { id: taskId },
      include: {
        project: {
          include: {
            workspace: {
              include: {
                members: { where: { userId: req.userId! } },
              },
            },
          },
        },
      },
    });

    if (!task) {
      return res.status(404).json({ success: false, error: "Task not found" });
    }

    if (task.project.workspace.members.length === 0) {
      return res.status(403).json({
        success: false,
        error: "Forbidden: Not a workspace member",
      });
    }

    const attachments = await prisma.attachment.findMany({
      where: { taskId },
      select: {
        id: true,
        filename: true,
        size: true,
        mimeType: true,
        createdAt: true,
      },
      orderBy: { createdAt: "desc" },
    });

    res.json({ success: true, data: attachments });
  } catch (error) {
    next(error);
  }
});

// POST /api/v1/attachments/avatar/presign — Presign avatar upload scoped strictly to req.userId
router.post("/avatar/presign", async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const parsed = avatarPresignSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid payload",
      });
    }

    const { filename, fileType, fileSize } = parsed.data;
    const validation = validateFileUpload(filename, fileType, fileSize, "avatar");
    if (!validation.valid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    const safeFilename = validation.sanitizedFilename || filename;
    const key = generateS3Key("avatars", req.userId!, safeFilename);
    const uploadUrl = await createPresignedUploadUrl({
      key,
      contentType: fileType.trim().toLowerCase(),
      contentLength: fileSize,
      bucket: S3_BUCKET_NAME,
      expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
    });

    res.json({
      success: true,
      data: {
        uploadUrl,
        key,
        bucket: S3_BUCKET_NAME,
        expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
        filename: safeFilename,
      },
    });
  } catch (error) {
    next(error);
  }
});

// PUT /api/v1/attachments/avatar/confirm — Verify avatar in S3 & update ONLY authenticated user
router.put("/avatar/confirm", async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const parsed = avatarConfirmSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid payload",
      });
    }

    const { key, fileType } = parsed.data;
    if (!validateS3ObjectKey(key, "avatars", req.userId!)) {
      return res.status(403).json({
        success: false,
        error: "Forbidden: Avatar object key does not belong to the authenticated user",
      });
    }

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

    const s3Verification = await verifyUploadedS3Object({
      key,
      expectedMimeType: inferredMime,
      purpose: "avatar",
      bucket: S3_BUCKET_NAME,
    });

    if (!s3Verification.valid) {
      return res.status(400).json({
        success: false,
        error: s3Verification.error || "Uploaded avatar failed security verification",
      });
    }

    const updatedUser = await prisma.user.update({
      where: { id: req.userId! },
      data: { image: `s3://${S3_BUCKET_NAME}/${key}` },
      select: { id: true, name: true, email: true, image: true, updatedAt: true },
    });

    res.json({ success: true, data: updatedUser });
  } catch (error) {
    next(error);
  }
});

// GET /api/v1/attachments/:id/download — Generate presigned GET URL with workspace & size verification
router.get("/:id/download", async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const attachmentId = String(req.params.id);
    const attachment = await prisma.attachment.findUnique({
      where: { id: attachmentId },
      include: {
        task: {
          include: {
            project: {
              include: {
                workspace: {
                  include: {
                    members: { where: { userId: req.userId! } },
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!attachment) {
      return res.status(404).json({ success: false, error: "Attachment not found" });
    }

    if (attachment.task.project.workspace.members.length === 0) {
      return res.status(403).json({ success: false, error: "Forbidden: Not a workspace member" });
    }

    const key = extractS3KeyFromUrl(attachment.url);
    const downloadCheck = await verifyS3ObjectForDownload({
      key,
      taskId: attachment.taskId,
      mimeType: attachment.mimeType,
      recordedSize: attachment.size,
      bucket: S3_BUCKET_NAME,
    });

    if (!downloadCheck.valid) {
      return res.status(400).json({
        success: false,
        error: downloadCheck.error || "Attachment failed download security checks",
      });
    }

    const downloadUrl = await createPresignedDownloadUrl({
      key,
      filename: attachment.filename,
      bucket: S3_BUCKET_NAME,
      expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
    });

    res.json({
      success: true,
      data: {
        downloadUrl,
        filename: attachment.filename,
        size: downloadCheck.actualSize ?? attachment.size,
        mimeType: attachment.mimeType,
        expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
      },
    });
  } catch (error) {
    next(error);
  }
});

export { router as attachmentRoutes };
