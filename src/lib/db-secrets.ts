// ═══════════════════════════════════════════════════════════════
//  TASKFLOW — AWS Secrets Manager Runtime RDS Credential Loader
//  Uses AWS IAM Instance Profile (defaultProvider) + AWS SigV4
//  to securely fetch and refresh rotated RDS PostgreSQL credentials.
// ═══════════════════════════════════════════════════════════════

import crypto from "crypto";
import { defaultProvider } from "@aws-sdk/credential-provider-node";

export interface RdsSecretPayload {
  username: string;
  password: string;
  host?: string;
  port?: string | number;
  dbname?: string;
}

function hmacSha256(key: string | Buffer, data: string): Buffer {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest();
}

function sha256Hex(data: string): string {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Signs and sends a Secrets Manager GetSecretValue request using AWS SigV4
 * and the default AWS credential provider chain (EC2 IAM role / IMDSv2).
 */
export async function fetchRdsSecretFromSecretsManager(params: {
  secretArn: string;
  region?: string;
  fetchImpl?: typeof fetch;
}): Promise<RdsSecretPayload> {
  const {
    secretArn,
    region = process.env.AWS_REGION || "ap-south-1",
    fetchImpl = fetch,
  } = params;

  if (!secretArn) {
    throw new Error("DB_SECRET_ARN is required to fetch RDS credentials from Secrets Manager");
  }

  const credentials = await defaultProvider()();
  const service = "secretsmanager";
  const host = `${service}.${region}.amazonaws.com`;
  const endpoint = `https://${host}/`;
  const target = "secretsmanager.GetSecretValue";
  const body = JSON.stringify({ SecretId: secretArn });

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(body);

  const canonicalHeadersList: Array<[string, string]> = [
    ["content-type", "application/x-amz-json-1.1"],
    ["host", host],
    ["x-amz-date", amzDate],
    ["x-amz-target", target],
  ];

  if (credentials.sessionToken) {
    canonicalHeadersList.push(["x-amz-security-token", credentials.sessionToken]);
  }

  canonicalHeadersList.sort((a, b) => a[0].localeCompare(b[0]));

  const canonicalHeaders = canonicalHeadersList
    .map(([k, v]) => `${k}:${v}\n`)
    .join("");
  const signedHeaders = canonicalHeadersList.map(([k]) => k).join(";");

  const canonicalRequest = [
    "POST",
    "/",
    "",
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = hmacSha256(`AWS4${credentials.secretAccessKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, "aws4_request");
  const signature = crypto
    .createHmac("sha256", kSigning)
    .update(stringToSign, "utf8")
    .digest("hex");

  const authorization = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/x-amz-json-1.1",
    "X-Amz-Date": amzDate,
    "X-Amz-Target": target,
    Authorization: authorization,
  };
  if (credentials.sessionToken) {
    headers["X-Amz-Security-Token"] = credentials.sessionToken;
  }

  const response = await fetchImpl(endpoint, {
    method: "POST",
    headers,
    body,
  });

  if (!response.ok) {
    throw new Error(`Secrets Manager GetSecretValue failed with HTTP ${response.status}`);
  }

  const data = (await response.json()) as { SecretString?: string };
  if (!data.SecretString) {
    throw new Error("Secrets Manager response did not contain SecretString");
  }

  const parsed = JSON.parse(data.SecretString) as Partial<RdsSecretPayload>;
  if (!parsed.username || !parsed.password) {
    throw new Error("RDS secret JSON is missing required username or password fields");
  }

  return {
    username: parsed.username,
    password: parsed.password,
    host: parsed.host,
    port: parsed.port,
    dbname: parsed.dbname,
  };
}

/**
 * Builds a properly URL-encoded PostgreSQL connection string enforcing TLS for RDS.
 */
export function buildRdsDatabaseUrl(params: {
  username: string;
  password: string;
  host: string;
  port?: string | number;
  dbname?: string;
  sslMode?: "require" | "verify-full" | "prefer";
}): string {
  const {
    username,
    password,
    host,
    port = 5432,
    dbname = "taskflow",
    sslMode = "require",
  } = params;

  const encodedUser = encodeURIComponent(username);
  const encodedPass = encodeURIComponent(password);
  return `postgresql://${encodedUser}:${encodedPass}@${host}:${port}/${dbname}?schema=public&sslmode=${sslMode}`;
}

/**
 * Detects Prisma / PostgreSQL authentication failures (e.g., after secret rotation).
 */
export function isDatabaseAuthError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const err = error as { code?: string; message?: string };
  if (err.code === "P1000" || err.code === "28P01") {
    return true;
  }
  const msg = (err.message || "").toLowerCase();
  return (
    msg.includes("password authentication failed") ||
    msg.includes("authentication failed against database server") ||
    msg.includes("28p01")
  );
}
