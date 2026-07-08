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

    const formData = new FormData(event.currentTarget);
    const response = await fetch("/api/scan", {
      method: "POST",
      body: formData,
    });
    const data = (await response.json()) as { error?: string; summary?: { totalUniqueDomains: number; totalRows: number } };

    if (!response.ok) {
      setState({ status: "error", message: data.error ?? "Scan failed. Please try again." });
      return;
    }

    setState({
      status: "success",
      message: `Report queued and emailed. Scanned ${data.summary?.totalUniqueDomains ?? 0} unique domains across ${data.summary?.totalRows ?? 0} rows.`,
    });
    event.currentTarget.reset();
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
      <p className="fine-print">MVP limits: 1 MB CSV, 5,000 rows, 500 unique domains.</p>
      {state.status === "success" ? <p className="form-status success">{state.message}</p> : null}
      {state.status === "error" ? <p className="form-status error">{state.message}</p> : null}
    </form>
  );
}
