"use client";

import { useState } from "react";

type SubmitState =
  | { status: "idle" }
  | { status: "submitting" }
  | { status: "success"; message: string }
  | { status: "error"; message: string };

export function UploadForm() {
  const [state, setState] = useState<SubmitState>({ status: "idle" });

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setState({ status: "submitting" });

    // React nulls out currentTarget once the handler returns, and a scan takes
    // ~30s — so hold the form element across the await instead of re-reading it.
    const form = event.currentTarget;
    const formData = new FormData(form);

    try {
      const response = await fetch("/api/scan", { method: "POST", body: formData });
      const data = (await response.json()) as { error?: string; summary?: { totalUniqueDomains: number; totalRows: number } };

      if (!response.ok) {
        setState({ status: "error", message: data.error ?? "Scan failed. Please try again." });
        return;
      }

      setState({
        status: "success",
        message: `Report queued and emailed. Scanned ${data.summary?.totalUniqueDomains ?? 0} unique domains across ${data.summary?.totalRows ?? 0} rows.`,
      });
      form.reset();
    } catch {
      // Without this the button stays stuck on "Scanning domains..." forever.
      setState({ status: "error", message: "Network error. Check your connection and try again." });
    }
  }

  return (
    <form className="upload-card" onSubmit={onSubmit}>
      <label>
        Report email
        <input name="email" type="email" placeholder="you@company.com" required disabled={state.status === "submitting"} />
      </label>
      <label>
        Prospect CSV
        <input name="file" type="file" accept=".csv,text/csv" required disabled={state.status === "submitting"} />
      </label>
      <button type="submit" disabled={state.status === "submitting"}>
        {state.status === "submitting" ? "Scanning domains..." : "Scan and email enriched CSV"}
      </button>
      <p className="fine-print">Limits: 25 MB CSV, 25,000 rows, 10,000 unique domains.</p>
      {state.status === "success" ? <p className="form-status success">{state.message}</p> : null}
      {state.status === "error" ? <p className="form-status error">{state.message}</p> : null}
    </form>
  );
}
