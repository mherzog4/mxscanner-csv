"use client";

import { useEffect, useRef, useState } from "react";

type SubmitState =
  | { status: "idle" }
  | { status: "submitting" }
  | { status: "running"; message: string }
  | { status: "success"; message: string }
  | { status: "error"; message: string };

const POLL_MS = 3000;

export function UploadForm() {
  const [state, setState] = useState<SubmitState>({ status: "idle" });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Clear the interval if this unmounts mid-job, or it keeps hitting the status
  // endpoint for a job nobody is watching.
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  function startPolling(runId: string, domainCount: number, rowCount: number) {
    if (pollRef.current) clearInterval(pollRef.current);

    pollRef.current = setInterval(async () => {
      try {
        const response = await fetch(`/api/scan/status?runId=${encodeURIComponent(runId)}`);
        if (!response.ok) return; // Transient lookup failure — keep polling.

        const data = (await response.json()) as { status?: string };

        // status is typed as a plain string, so anything unrecognised counts as still
        // running rather than being guessed at.
        if (data.status === "completed") {
          if (pollRef.current) clearInterval(pollRef.current);
          setState({
            status: "success",
            message: `Done. Scanned ${domainCount.toLocaleString()} unique domains across ${rowCount.toLocaleString()} rows — the enriched CSV is on its way to your inbox.`,
          });
        } else if (data.status === "failed") {
          if (pollRef.current) clearInterval(pollRef.current);
          setState({
            status: "error",
            message: "The scan failed partway through and no report was sent. Please try again.",
          });
        }
      } catch {
        // A network blip while polling is not a job failure — the job runs server-side.
      }
    }, POLL_MS);
  }

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setState({ status: "submitting" });

    // React nulls out currentTarget once the handler returns, so hold the element
    // across the await instead of re-reading it.
    const form = event.currentTarget;
    const formData = new FormData(form);

    try {
      const response = await fetch("/api/scan", { method: "POST", body: formData });
      const data = (await response.json()) as {
        error?: string;
        runId?: string;
        domainCount?: number;
        rowCount?: number;
      };

      if (!response.ok) {
        setState({ status: "error", message: data.error ?? "Scan failed. Please try again." });
        return;
      }

      const domainCount = data.domainCount ?? 0;
      const rowCount = data.rowCount ?? 0;

      setState({
        status: "running",
        message: `Scanning ${domainCount.toLocaleString()} unique domains from ${rowCount.toLocaleString()} rows. You can close this tab — the report is emailed when it finishes.`,
      });
      form.reset();

      if (data.runId) startPolling(data.runId, domainCount, rowCount);
    } catch {
      setState({ status: "error", message: "Network error. Check your connection and try again." });
    }
  }

  const busy = state.status === "submitting" || state.status === "running";

  return (
    <form className="upload-card" onSubmit={onSubmit}>
      <label>
        Report email
        <input name="email" type="email" placeholder="you@company.com" required disabled={busy} />
      </label>
      <label>
        Prospect CSV
        <input name="file" type="file" accept=".csv,text/csv" required disabled={busy} />
      </label>
      <label className="checkbox-row">
        <input name="includeDkim" type="checkbox" disabled={busy} />
        <span>
          Probe DKIM selectors
          <em>More than doubles DNS work, so the domain limit drops to 1,500.</em>
        </span>
      </label>
      <button type="submit" disabled={busy}>
        {state.status === "submitting"
          ? "Uploading..."
          : state.status === "running"
            ? "Scanning..."
            : "Scan and email enriched CSV"}
      </button>
      <p className="fine-print">Limits: 25 MB CSV, 25,000 rows, 3,500 unique domains.</p>
      {state.status === "running" ? <p className="form-status running">{state.message}</p> : null}
      {state.status === "success" ? <p className="form-status success">{state.message}</p> : null}
      {state.status === "error" ? <p className="form-status error">{state.message}</p> : null}
    </form>
  );
}
