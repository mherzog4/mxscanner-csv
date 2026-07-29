import { NextResponse } from "next/server";
import { getRun } from "workflow/api";

export const runtime = "nodejs";

// Polled by the upload form while a job runs. Deliberately thin: it reports run state
// and nothing about the CSV, so it cannot leak scan contents to anyone holding a runId.
export async function GET(request: Request) {
  const runId = new URL(request.url).searchParams.get("runId");

  if (!runId) {
    return NextResponse.json({ error: "Missing runId." }, { status: 400 });
  }

  try {
    const run = getRun(runId);
    const status = await run.status;

    return NextResponse.json(
      { runId, status },
      // Never cache a status poll — a stale "running" would strand the form.
      { headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    console.error(`Status lookup failed for ${runId}:`, error);
    return NextResponse.json({ error: "Could not read job status." }, { status: 404 });
  }
}
