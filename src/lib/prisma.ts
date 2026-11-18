// ═══════════════════════════════════════════════════════════════
//  TASKFLOW — Prisma Client Singleton with Rotation Reconnect
//  Preserves local Docker PostgreSQL and supports AWS RDS
//  credential refresh from AWS Secrets Manager on auth errors.
// ═══════════════════════════════════════════════════════════════

import { PrismaClient } from "@prisma/client";
import {
  buildRdsDatabaseUrl,
  fetchRdsSecretFromSecretsManager,
  isDatabaseAuthError,
} from "./db-secrets";

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

function createPrismaClient(databaseUrl?: string): PrismaClient {
  return new PrismaClient({
    ...(databaseUrl ? { datasources: { db: { url: databaseUrl } } } : {}),
    log:
      process.env.NODE_ENV === "development"
        ? ["query", "error", "warn"]
        : ["error"],
  });
}

let activePrisma: PrismaClient =
  globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = activePrisma;
}

let refreshInFlight: Promise<PrismaClient> | null = null;

/**
 * Re-fetches RDS credentials from AWS Secrets Manager, disconnects the stale
 * Prisma connection pool, and initializes a fresh PrismaClient with rotated credentials.
 */
export async function refreshPrismaFromSecretsManager(
  secretLoader = fetchRdsSecretFromSecretsManager
): Promise<PrismaClient> {
  const secretArn = process.env.DB_SECRET_ARN;
  if (!secretArn) {
    throw new Error("Cannot refresh credentials: DB_SECRET_ARN is not configured");
  }

  if (refreshInFlight) {
    return refreshInFlight;
  }

  refreshInFlight = (async () => {
    try {
      const secret = await secretLoader({
        secretArn,
        region: process.env.AWS_REGION || "ap-south-1",
      });

      const host = secret.host || process.env.RDS_ENDPOINT;
      const port = secret.port || process.env.RDS_PORT || "5432";
      const dbname = secret.dbname || process.env.DB_NAME || "taskflow";

      if (!host) {
        throw new Error("RDS host is missing from both Secrets Manager payload and RDS_ENDPOINT");
      }

      const rotatedUrl = buildRdsDatabaseUrl({
        username: secret.username,
        password: secret.password,
        host,
        port,
        dbname,
        sslMode: "require",
      });

      process.env.DATABASE_URL = rotatedUrl;
      process.env.DIRECT_DATABASE_URL = rotatedUrl;

      const previousClient = activePrisma;
      const nextClient = createPrismaClient(rotatedUrl);
      await nextClient.$connect();

      activePrisma = nextClient;
      if (process.env.NODE_ENV !== "production") {
        globalForPrisma.prisma = activePrisma;
      }

      await previousClient.$disconnect().catch(() => null);
      return activePrisma;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

/**
 * Executes a Prisma database operation and automatically refreshes RDS credentials
 * from AWS Secrets Manager once if PostgreSQL rejects the current password (e.g. post-rotation).
 */
export async function withDbAuthRetry<T>(
  operation: (client: PrismaClient) => Promise<T>,
  secretLoader = fetchRdsSecretFromSecretsManager
): Promise<T> {
  try {
    return await operation(activePrisma);
  } catch (error) {
    if (process.env.DB_SECRET_ARN && isDatabaseAuthError(error)) {
      const refreshedClient = await refreshPrismaFromSecretsManager(secretLoader);
      return await operation(refreshedClient);
    }
    throw error;
  }
}

// Proxy ensures existing `prisma.<model>` imports automatically delegate to the
// latest activePrisma instance even after a runtime Secrets Manager credential rotation.
export const prisma: PrismaClient = new Proxy({} as PrismaClient, {
  get(_target, prop, receiver) {
    const value = Reflect.get(activePrisma, prop, receiver);
    return typeof value === "function" ? value.bind(activePrisma) : value;
  },
});

export default prisma;
