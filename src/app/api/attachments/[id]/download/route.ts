export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import { getAuthenticatedUser } from "@/lib/auth-guard";
import prisma from "@/lib/prisma";
import {
  createPresignedDownloadUrl,
  extractS3KeyFromUrl,
  verifyS3ObjectForDownload,
  S3_BUCKET_NAME,
  PRESIGNED_URL_EXPIRY_SECONDS,
} from "@/lib/s3";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: attachmentId } = await params;

    // 1. Strictly authenticate user (no demo fallback)
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ error: "Unauthorized access" }, { status: 401 });
    }

    // 2. Query attachment with task & workspace security boundary checks
    const attachment = await prisma.attachment.findUnique({
      where: { id: attachmentId },
      include: {
        task: {
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
        },
      },
    });

    if (!attachment) {
      return NextResponse.json({ error: "Attachment not found" }, { status: 404 });
    }

    // 3. Enforce workspace membership (blocks cross-workspace downloads)
    const isMember = attachment.task.project.workspace.members.length > 0;
    if (!isMember) {
      return NextResponse.json(
        { error: "Forbidden: You do not have permission to download this attachment" },
        { status: 403 }
      );
    }

    // 4. Extract S3 key and verify key scope & actual stored object size before signing download URL
    const key = extractS3KeyFromUrl(attachment.url);
    const downloadCheck = await verifyS3ObjectForDownload({
      key,
      taskId: attachment.taskId,
      mimeType: attachment.mimeType,
      recordedSize: attachment.size,
      bucket: S3_BUCKET_NAME,
    });

    if (!downloadCheck.valid) {
      return NextResponse.json(
        { error: downloadCheck.error || "Attachment failed download security checks" },
        { status: 400 }
      );
    }

    // 5. Generate 300-second short-lived presigned download URL
    const downloadUrl = await createPresignedDownloadUrl({
      key,
      filename: attachment.filename,
      bucket: S3_BUCKET_NAME,
      expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
    });

    return NextResponse.json({
      downloadUrl,
      filename: attachment.filename,
      size: downloadCheck.actualSize ?? attachment.size,
      mimeType: attachment.mimeType,
      expiresIn: PRESIGNED_URL_EXPIRY_SECONDS,
    });
  } catch (error) {
    console.error("[Download Attachment Error]:", error);
    return NextResponse.json(
      { error: "Internal server error generating download URL" },
      { status: 500 }
    );
  }
}
