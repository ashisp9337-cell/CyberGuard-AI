import type { AnalysisResult, ScanStage, SubtopicConfig, UploadedFileMeta } from "@/types";
import type { DetectionModule } from "@/types";
import { fakeHash } from "@/lib/utils";
import { API_CONFIG } from "./config";
import { apiClient } from "./client";

export const STANDARD_SCAN_STAGES: ScanStage[] = [
  { id: "prepare", label: "Preparing Analysis" },
  { id: "hash", label: "Calculating Hash" },
  { id: "extract", label: "Extracting Features" },
  { id: "intel", label: "Checking Threat Intelligence" },
  { id: "static", label: "Static Analysis" },
  { id: "behavioral", label: "Behavioral Pattern Analysis" },
  { id: "ai", label: "AI Risk Evaluation" },
  { id: "report", label: "Generating Security Report" },
];

export interface RunAnalysisInput {
  module: DetectionModule;
  subtopic: SubtopicConfig;
  textInput?: string;
  urlInput?: string;
  file?: UploadedFileMeta;
  /** The actual browser File object, required to upload to the real backend. */
  fileBlob?: File;
  extraFieldValues?: Record<string, string>;
}

/**
 * Runs a real scan against the CyberGuard backend (POST /api/analysis/scan).
 * The stage progression below is a UX affordance — actual detection work
 * (ML inference, rule evaluation, DB write) happens server-side while these
 * stages animate; if the server responds before the animation finishes we
 * let the animation catch up, and if it takes longer we hold on the last
 * "AI Risk Evaluation" stage rather than lying about completion.
 */
export async function runAnalysis(
  input: RunAnalysisInput,
  onStage?: (stage: ScanStage, index: number, total: number) => void,
): Promise<AnalysisResult> {
  if (API_CONFIG.useMockData) {
    const { runMockAnalysis } = await import("./mockAnalysisFallback");
    return runMockAnalysis(input, onStage);
  }

  const { module: mod, subtopic } = input;

  const form = new FormData();
  form.append("moduleId", mod.id);
  form.append("subtopicId", subtopic.id);
  form.append("subtopicTitle", subtopic.title);
  if (input.textInput) form.append("textInput", input.textInput);
  if (input.urlInput) form.append("urlInput", input.urlInput);
  if (input.extraFieldValues) form.append("extraFieldValues", JSON.stringify(input.extraFieldValues));
  if (input.fileBlob) form.append("file", input.fileBlob, input.file?.name ?? input.fileBlob.name);

  let stageIndex = 0;
  const stageTimer = setInterval(() => {
    if (stageIndex < STANDARD_SCAN_STAGES.length - 1) {
      onStage?.(STANDARD_SCAN_STAGES[stageIndex], stageIndex, STANDARD_SCAN_STAGES.length);
      stageIndex++;
    }
  }, 260);
  onStage?.(STANDARD_SCAN_STAGES[0], 0, STANDARD_SCAN_STAGES.length);

  try {
    const result = await apiClient.post<AnalysisResult>("/api/analysis/scan", form, { timeoutMs: 60000 });
    clearInterval(stageTimer);
    onStage?.(STANDARD_SCAN_STAGES[STANDARD_SCAN_STAGES.length - 1], STANDARD_SCAN_STAGES.length - 1, STANDARD_SCAN_STAGES.length);
    return result;
  } catch (err) {
    clearInterval(stageTimer);
    throw err;
  }
}

export function hashForFile(name: string): string {
  return fakeHash(name + Date.now());
}
