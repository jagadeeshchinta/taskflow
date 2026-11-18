export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import { getAuthenticatedUser } from "@/lib/auth-guard";
import prisma from "@/lib/prisma";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await getAuthenticatedUser();
    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id: taskId } = await params;

    const task = await prisma.task.findUnique({
      where: { id: taskId },
      include: {
        project: {
          include: {
            workspace: {
              include: {
                members: {
                  where: { userId: user.id },
                },
              },
            },
          },
        },
      },
    });

    if (!task) {
      return NextResponse.json({ error: "Task not found" }, { status: 404 });
    }

    const isMember = task.project.workspace.members.length > 0;
    if (!isMember) {
      return NextResponse.json(
        { error: "Forbidden: You do not have access to this task's attachments" },
        { status: 403 }
      );
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

    return NextResponse.json({
      attachments: attachments.map((a) => ({
        ...a,
        createdAt: a.createdAt.toISOString(),
      })),
    });
  } catch (error) {
    console.error("[Task Attachments GET Error]:", error);
    return NextResponse.json(
      { error: "Failed to load task attachments" },
      { status: 500 }
    );
  }
}
