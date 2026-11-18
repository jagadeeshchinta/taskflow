export const dynamic = "force-dynamic";

import { NextResponse } from "next/server";
import {
  isMockS3Enabled,
  putMockS3Object,
  getMockS3Object,
  sanitizeFilename,
} from "@/lib/s3";

// Dev/test-only local S3 simulator for credential-free E2E testing.
// Always returns 404 in production or when MOCK_S3 !== "true".
export async function PUT(req: Request) {
  if (!isMockS3Enabled()) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const { searchParams } = new URL(req.url);
  const key = searchParams.get("key");
  const contentType = req.headers.get("content-type") || searchParams.get("contentType") || "application/octet-stream";

  if (!key || key.includes("..") || key.startsWith("/")) {
    return NextResponse.json({ error: "Invalid mock key" }, { status: 400 });
  }

  const arrayBuffer = await req.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);

  putMockS3Object(key, buffer, contentType);
  return new NextResponse(null, { status: 200 });
}

export async function GET(req: Request) {
  if (!isMockS3Enabled()) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const { searchParams } = new URL(req.url);
  const key = searchParams.get("key");
  const filename = sanitizeFilename(searchParams.get("filename") || "download");

  if (!key || key.includes("..") || key.startsWith("/")) {
    return NextResponse.json({ error: "Invalid mock key" }, { status: 400 });
  }

  const obj = getMockS3Object(key);
  if (!obj) {
    return NextResponse.json({ error: "Object not found" }, { status: 404 });
  }

  return new NextResponse(new Uint8Array(obj.body), {
    status: 200,
    headers: {
      "Content-Type": obj.contentType,
      "Content-Length": String(obj.body.length),
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
