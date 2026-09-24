import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useToast } from "@/context/ToastContext";
import { listReports, createReport, downloadReportUrl } from "@/services/api/reportsService";
import { formatDate } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import type { SecurityReport } from "@/types";

const REPORT_TYPES = [
  "Executive Security Summary",
  "Threat Analysis Report",
  "Malware Analysis Report",
  "Phishing Investigation Report",
  "Account Security Report",
  "Network Security Report",
];

export default function Reports() {
  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedType, setSelectedType] = useState(REPORT_TYPES[0]);
  const [generating, setGenerating] = useState(false);
  const { notify } = useToast();

  function refresh() {
    listReports().then(setReports).catch(() => {}).finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  async function handleGenerate() {
    setGenerating(true);
    try {
      const title = `${selectedType} — ${new Date().toLocaleDateString(undefined, { month: "short", day: "numeric" })}`;
      const newReport = await createReport(title, "PDF");
      setReports((prev) => [newReport, ...prev]);
      notify({ variant: "success", title: "Report generated", description: newReport.title });
    } catch (err) {
      notify({ variant: "critical", title: "Could not generate report", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setGenerating(false);
    }
  }

  async function handleExport(format: "PDF" | "JSON" | "CSV", report: SecurityReport) {
    try {
      if (report.format === format) {
        window.open(downloadReportUrl(report.id), "_blank");
        return;
      }
      const generated = await createReport(report.title, format);
      setReports((prev) => [generated, ...prev]);
      window.open(downloadReportUrl(generated.id), "_blank");
    } catch (err) {
      notify({ variant: "critical", title: `Could not export as ${format}`, description: err instanceof Error ? err.message : "Please try again." });
    }
  }

  return (
    <div>
      <PageHeader title="Reports" subtitle="Generate and export security reports for stakeholders and incident response." />

      <Card className="mb-5">
        <CardHeader title="Generate New Report" icon={<ICONS.reports size={16} />} />
        <CardBody className="flex flex-col sm:flex-row items-stretch sm:items-end gap-3">
          <div className="flex-1">
            <label htmlFor="report-type" className="block text-xs font-medium text-slate-300 mb-1.5">Report Type</label>
            <select
              id="report-type"
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="w-full rounded-lg bg-elevated border border-strong px-3 py-2.5 text-sm text-white focus-ring"
            >
              {REPORT_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <Button onClick={handleGenerate} disabled={generating} size="lg">
            {generating ? <ICONS.refresh size={15} className="animate-spin" /> : <ICONS.zap size={15} />}
            {generating ? "Generating..." : "Generate Report"}
          </Button>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Report History" subtitle={`${reports.length} reports`} icon={<ICONS.scanHistory size={16} />} />
        <CardBody className="space-y-2.5">
          {loading && <p className="text-sm text-slate-500 py-6 text-center">Loading…</p>}
          {!loading && reports.length === 0 && (
            <p className="text-sm text-slate-500 py-6 text-center">No reports yet — generate one above.</p>
          )}
          {reports.map((r) => (
            <div key={r.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-default bg-elevated p-3.5">
              <div className="flex items-center gap-3 min-w-0">
                <div className="h-9 w-9 rounded-lg bg-cyan-500/10 flex items-center justify-center shrink-0">
                  <ICONS.reports size={17} className="text-cyan-400" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-white truncate">{r.title}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{formatDate(r.createdAt)} &middot; {r.sizeKb} KB</p>
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <Button size="sm" variant="secondary" onClick={() => handleExport("PDF", r)}><ICONS.download size={13} /> PDF</Button>
                <Button size="sm" variant="outline" onClick={() => handleExport("JSON", r)}>JSON</Button>
                <Button size="sm" variant="outline" onClick={() => handleExport("CSV", r)}>CSV</Button>
              </div>
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  );
}
