// ═══════════════════════════════════════════════════════════════
//  TASKFLOW — RDS Secrets Manager Rotation Reconnection Test
//  Verifies that Prisma disconnects stale pool, fetches rotated
//  RDS secret from AWS Secrets Manager, and retries transparently.
// ═══════════════════════════════════════════════════════════════

const mockConnect = jest.fn().mockResolvedValue(undefined);
const mockDisconnect = jest.fn().mockResolvedValue(undefined);
const constructedUrls: Array<string | undefined> = [];

jest.mock("@prisma/client", () => {
  return {
    PrismaClient: jest.fn().mockImplementation((opts?: { datasources?: { db?: { url?: string } } }) => {
      const url = opts?.datasources?.db?.url;
      constructedUrls.push(url);
      return {
        _datasourceUrl: url,
        $connect: mockConnect,
        $disconnect: mockDisconnect,
      };
    }),
  };
});

import { withDbAuthRetry } from "@/lib/prisma";

describe("RDS Secrets Manager Credential Rotation Reconnection", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.DB_SECRET_ARN = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:taskflow/prod/rds-credentials";
    process.env.RDS_ENDPOINT = "taskflow-prod-postgres.mock.ap-south-1.rds.amazonaws.com";
    process.env.RDS_PORT = "5432";
    process.env.DB_NAME = "taskflow";
    process.env.AWS_REGION = "ap-south-1";
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  test("catches Prisma P1000 auth error after password rotation, fetches new secret, reconnects, and succeeds", async () => {
    const mockSecretLoader = jest.fn().mockResolvedValue({
      username: "taskflowadmin",
      password: "NewRotatedPassword!2026",
    });

    let attempt = 0;
    const result = await withDbAuthRetry(async (client) => {
      attempt += 1;
      if (attempt === 1) {
        const authErr = Object.assign(new Error("Authentication failed against database server"), {
          code: "P1000",
        });
        throw authErr;
      }
      return {
        ok: true,
        urlUsed: (client as unknown as { _datasourceUrl?: string })._datasourceUrl,
      };
    }, mockSecretLoader);

    expect(attempt).toBe(2);
    expect(mockSecretLoader).toHaveBeenCalledTimes(1);
    expect(mockConnect).toHaveBeenCalledTimes(1);
    expect(mockDisconnect).toHaveBeenCalledTimes(1);
    expect(result.ok).toBe(true);
    expect(result.urlUsed).toContain("NewRotatedPassword!2026");
    expect(result.urlUsed).toContain("sslmode=require");
  });

  test("does not trigger Secrets Manager when DB_SECRET_ARN is unset (local Docker PostgreSQL mode)", async () => {
    delete process.env.DB_SECRET_ARN;
    const mockSecretLoader = jest.fn();

    await expect(
      withDbAuthRetry(async () => {
        throw Object.assign(new Error("password authentication failed"), { code: "28P01" });
      }, mockSecretLoader)
    ).rejects.toThrow("password authentication failed");

    expect(mockSecretLoader).not.toHaveBeenCalled();
  });
});
