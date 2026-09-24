// Local, browser-only mock analysis (no backend required). Used only when
// VITE_USE_MOCK_DATA=true, for offline UI development/demos. The real path
// is analysisService.ts calling the live CyberGuard backend.
import type { AnalysisResult, DetectedIndicator, ScanStage } from "@/types";
import { generateId, truncate } from "@/lib/utils";
import { classifyRisk, severityFromClassification, recommendationsFor } from "@/lib/severity";
import type { RunAnalysisInput } from "./analysisService";
import { STANDARD_SCAN_STAGES } from "./analysisService";

function pickIndicators(subtopic: RunAnalysisInput["subtopic"], seed: string): DetectedIndicator[] {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  const rand = () => {
    h = (h * 1664525 + 1013904223) >>> 0;
    return h / 4294967295;
  };
  return subtopic.indicatorPool.map((tpl) => {
    const triggerChance = 0.3 + tpl.weight / 100;
    const triggered = rand() < Math.min(triggerChance, 0.85);
    return { ...tpl, id: generateId("IND"), triggered };
  });
}

function buildExplanation(subtopic: RunAnalysisInput["subtopic"], indicators: DetectedIndicator[], classification: ReturnType<typeof classifyRisk>): string {
  const triggered = indicators.filter((i) => i.triggered);
  if (classification === "safe") {
    return `No significant indicators of ${subtopic.title.toLowerCase()} concerns were detected (mock/offline mode).`;
  }
  const top = [...triggered].sort((a, b) => b.weight - a.weight).slice(0, 3);
  const namedList = top.map((i) => i.label.toLowerCase()).join(", ");
  return `[MOCK MODE — no backend called] Detected ${triggered.length} indicator(s), most notably: ${namedList || "low-confidence structural anomalies"}.`;
}

export async function runMockAnalysis(
  input: RunAnalysisInput,
  onStage?: (stage: ScanStage, index: number, total: number) => void,
): Promise<AnalysisResult> {
  const { module: mod, subtopic } = input;
  const target = input.file?.name ?? input.urlInput ?? truncate(input.textInput ?? "Untitled submission", 60);
  const targetType = subtopic.inputKind;

  for (let i = 0; i < STANDARD_SCAN_STAGES.length; i++) {
    onStage?.(STANDARD_SCAN_STAGES[i], i, STANDARD_SCAN_STAGES.length);
    await new Promise((r) => setTimeout(r, 200 + Math.random() * 150));
  }

  const seed = `${subtopic.id}:${target}:${input.extraFieldValues ? JSON.stringify(input.extraFieldValues) : ""}`;
  const indicators = pickIndicators(subtopic, seed);
  const triggeredWeight = indicators.filter((i) => i.triggered).reduce((sum, i) => sum + i.weight, 0);
  const riskScore = Math.max(2, Math.min(99, Math.round(triggeredWeight * (0.85 + Math.random() * 0.3))));
  const classification = classifyRisk(riskScore);
  const severity = severityFromClassification(classification);

  return {
    scanId: generateId("SCN"),
    moduleId: mod.id,
    subtopicId: subtopic.id,
    subtopicTitle: subtopic.title,
    target,
    targetType,
    riskScore,
    classification,
    confidenceScore: Math.round(72 + Math.random() * 24),
    detectionTime: new Date().toISOString(),
    analysisEngine: `CYBERGUARD Mock Engine — ${mod.shortName} (offline demo mode)`,
    threatType: mod.shortName,
    severity,
    indicators,
    explanation: buildExplanation(subtopic, indicators, classification),
    recommendations: recommendationsFor(classification, mod.shortName),
    status: "completed",
  };
}
