import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { TextInput, TextArea } from "@/components/ui/Input";
import { FileUploader } from "@/components/analysis/FileUploader";
import { ScanProgressView } from "@/components/analysis/ScanProgressView";
import { ResultView } from "@/components/analysis/ResultView";
import { runAnalysis, type RunAnalysisInput } from "@/services/api/analysisService";
import { useToast } from "@/context/ToastContext";
import { useAppContext } from "@/context/AppContext";
import { ICONS } from "@/lib/icons";
import { generateId, formatBytes } from "@/lib/utils";
import type { DetectionModule, SubtopicConfig, AnalysisResult, UploadedFileMeta, ScanHistoryEntry } from "@/types";

type Phase = "form" | "scanning" | "result";

const URL_PATTERN = /^https?:\/\/[^\s]+\.[^\s]{2,}/i;
const MAX_TEXT_LEN = 8000;

export function AnalysisWorkspace({ module: mod, subtopic }: { module: DetectionModule; subtopic: SubtopicConfig }) {
  const [phase, setPhase] = useState<Phase>("form");
  const [stageIndex, setStageIndex] = useState(0);
  const [textValue, setTextValue] = useState("");
  const [urlValue, setUrlValue] = useState("");
  const [extraValues, setExtraValues] = useState<Record<string, string>>({});
  const [file, setFile] = useState<UploadedFileMeta | null>(null);
  const [fileBlob, setFileBlob] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const { notify } = useToast();
  const { addScanToHistory } = useAppContext();

  const needsFile = subtopic.inputKind === "file";
  // Auto-detect pages may take EITHER pasted text OR a file (e.g. phishing: a message or an .eml / QR image).
  const optionalFile = subtopic.id === "auto" && !needsFile && !!subtopic.acceptedFileTypes?.length;
  const needsUrl = subtopic.inputKind === "url";
  const needsText = subtopic.inputKind === "text" || subtopic.inputKind === "email" || subtopic.inputKind === "identity";

  function resetForm() {
    setPhase("form");
    setTextValue("");
    setUrlValue("");
    setExtraValues({});
    setFile(null);
    setFileBlob(null);
    setError(null);
    setResult(null);
  }

  function handleFileSelect(f: File) {
    const ext = "." + f.name.split(".").pop()?.toLowerCase();
    if (subtopic.acceptedFileTypes?.length && !subtopic.acceptedFileTypes.includes(ext)) {
      setError(`Unsupported file type. Accepted: ${subtopic.acceptedFileTypes.join(", ")}`);
      return;
    }
    const maxBytes = (subtopic.maxFileSizeMb ?? 50) * 1024 * 1024;
    if (f.size > maxBytes) {
      setError(`File too large. Maximum size is ${subtopic.maxFileSizeMb ?? 50}MB.`);
      return;
    }
    setError(null);
    const meta: UploadedFileMeta = { id: generateId("FILE"), name: f.name, size: f.size, type: f.type || ext, progress: 0 };
    setFile(meta);
    setFileBlob(f);
    notify({ variant: "info", title: "File uploaded", description: `${f.name} (${formatBytes(f.size)})` });
    let progress = 0;
    const iv = setInterval(() => {
      progress += 20 + Math.random() * 20;
      setFile((prev) => (prev ? { ...prev, progress: Math.min(100, progress) } : prev));
      if (progress >= 100) clearInterval(iv);
    }, 120);
  }

  function validate(): string | null {
    if (needsFile && !file) return "Please upload a file to analyze.";
    if (needsUrl) {
      if (!urlValue.trim()) return "Please enter a URL to analyze.";
      if (!URL_PATTERN.test(urlValue.trim())) return "Please enter a valid URL (e.g. https://example.com).";
    }
    if (needsText && !textValue.trim() && !(optionalFile && file)) return "Please paste content to analyze.";
    if (needsText && textValue.length > MAX_TEXT_LEN) return `Content is too long (max ${MAX_TEXT_LEN} characters).`;
    return null;
  }

  async function handleAnalyze() {
    const v = validate();
    if (v) {
      setError(v);
      notify({ variant: "warning", title: "Cannot start analysis", description: v });
      return;
    }
    setError(null);
    setPhase("scanning");
    setStageIndex(0);
    notify({ variant: "info", title: "Scan started", description: `Analyzing via ${subtopic.title}` });

    const input: RunAnalysisInput = {
      module: mod,
      subtopic,
      textInput: needsText ? textValue : undefined,
      urlInput: needsUrl ? urlValue : undefined,
      file: (needsFile || optionalFile) && file ? file : undefined,
      fileBlob: (needsFile || optionalFile) && fileBlob ? fileBlob : undefined,
      extraFieldValues: extraValues,
    };

    let res: AnalysisResult;
    try {
      res = await runAnalysis(input, (_stage, index) => setStageIndex(index));
    } catch (err) {
      setPhase("form");
      const message = err instanceof Error ? err.message : "The scan could not be completed. Please try again.";
      setError(message);
      notify({ variant: "critical", title: "Scan failed", description: message });
      return;
    }
    setResult(res);
    setPhase("result");

    const historyEntry: ScanHistoryEntry = {
      scanId: res.scanId,
      target: res.target,
      targetType: res.targetType,
      threatType: res.threatType,
      moduleId: res.moduleId,
      riskScore: res.riskScore,
      severity: res.severity,
      date: res.detectionTime,
      status: res.classification === "critical" || res.classification === "high_risk" ? "flagged" : res.classification === "safe" ? "cleared" : "completed",
    };
    addScanToHistory(historyEntry);

    if (res.classification === "critical") {
      notify({ variant: "critical", title: "Critical threat detected", description: res.threatType });
    } else if (res.classification === "high_risk") {
      notify({ variant: "warning", title: "High risk item flagged", description: res.threatType });
    } else if (res.classification === "safe") {
      notify({ variant: "success", title: "Analysis complete — no threats found" });
    } else {
      notify({ variant: "info", title: "Analysis complete", description: `Classified as ${res.classification.replace("_", " ")}` });
    }
  }

  return (
    <AnimatePresence mode="wait">
      {phase === "form" && (
        <motion.div key="form" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <Card>
            <CardHeader title={subtopic.title} subtitle={subtopic.supportedInput} icon={<ICONS.scan size={16} />} />
            <CardBody className="space-y-4">
              {needsUrl && (
                <TextInput
                  label="Target URL"
                  required
                  value={urlValue}
                  onChange={(e) => setUrlValue(e.target.value)}
                  placeholder={subtopic.placeholder ?? "https://example.com"}
                  error={error && !urlValue ? error : undefined}
                />
              )}
              {needsText && (
                <TextArea
                  label={subtopic.inputKind === "email" ? "Email content" : "Content to analyze"}
                  required
                  value={textValue}
                  onChange={(e) => setTextValue(e.target.value)}
                  placeholder={subtopic.placeholder}
                  hint={`${textValue.length}/${MAX_TEXT_LEN} characters`}
                  error={error && !textValue ? error : undefined}
                />
              )}
              {(needsFile || optionalFile) && (
                <FileUploader
                  accepted={subtopic.acceptedFileTypes}
                  maxSizeMb={subtopic.maxFileSizeMb ?? 50}
                  file={file}
                  onSelect={handleFileSelect}
                  onRemove={() => setFile(null)}
                  error={error ?? undefined}
                />
              )}

              {subtopic.extraFields?.map((f) => (
                <TextInput
                  key={f.id}
                  label={f.label}
                  placeholder={f.placeholder}
                  value={extraValues[f.id] ?? ""}
                  onChange={(e) => setExtraValues((prev) => ({ ...prev, [f.id]: e.target.value }))}
                />
              ))}

              {error && (needsFile ? false : (needsUrl && urlValue) || (needsText && textValue)) && (
                <p className="text-xs text-red-400" role="alert">
                  {error}
                </p>
              )}

              <div className="flex items-center justify-between pt-2">
                <p className="text-xs text-slate-500 flex items-center gap-1.5">
                  <ICONS.info size={13} /> Results come from CYBERGUARD's detection engines and are saved to your scan history.
                </p>
                <Button onClick={handleAnalyze} size="lg">
                  <ICONS.scan size={16} /> Analyze
                </Button>
              </div>
            </CardBody>
          </Card>
        </motion.div>
      )}

      {phase === "scanning" && (
        <motion.div key="scanning" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <ScanProgressView currentIndex={stageIndex} />
        </motion.div>
      )}

      {phase === "result" && result && (
        <motion.div key="result">
          <ResultView
            result={result}
            onNewScan={resetForm}
            onSave={() => notify({ variant: "success", title: "Report exported", description: `${result.scanId}.pdf` })}
          />
        </motion.div>
      )}
    </AnimatePresence>
  );
}
