// ═══════════════════════════════════════════════════════════════
//  TASKFLOW — Strict Authentication Guard (No Demo Fallback)
//  Used by security-sensitive endpoints (S3 uploads, downloads, avatars)
// ═══════════════════════════════════════════════════════════════

import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";

export interface AuthenticatedUser {
  id: string;
  email: string;
  name: string | null;
  image: string | null;
}

/**
 * Strictly resolves the currently authenticated NextAuth session user.
 * NEVER falls back to a demo/default user. Returns null when unauthenticated.
 */
export async function getAuthenticatedUser(): Promise<AuthenticatedUser | null> {
  const session = await auth().catch(() => null);
  const sessionUserId = session?.user?.id;

  if (!sessionUserId) {
    return null;
  }

  const user = await prisma.user.findUnique({
    where: { id: sessionUserId },
    select: {
      id: true,
      email: true,
      name: true,
      image: true,
    },
  });

  return user ?? null;
}
