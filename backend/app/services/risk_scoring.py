"""
Mirrors src/lib/severity.ts exactly so backend-computed classifications
and recommendations match what the existing frontend already renders.
"""


def classify_risk(score: int) -> str:
    if score <= 25:
        return "safe"
    if score <= 50:
        return "low_risk"
    if score <= 70:
        return "suspicious"
    if score <= 85:
        return "high_risk"
    return "critical"


def severity_from_classification(c: str) -> str:
    return {
        "safe": "low", "low_risk": "low", "suspicious": "medium",
        "high_risk": "high", "critical": "critical",
    }.get(c, "info")


def recommendations_for(c: str, threat_type: str) -> list[str]:
    t = threat_type.lower()
    if c == "safe":
        return [
            "No immediate action required.",
            "Continue routine monitoring.",
            f"No indicators of {t} were confirmed.",
        ]
    if c == "low_risk":
        return [
            "No urgent action required, but remain cautious.",
            "Re-scan if the source or context changes.",
            "Log this result for historical reference.",
        ]
    if c == "suspicious":
        return [
            "Review manually before interacting further.",
            "Avoid entering credentials or personal data.",
            "Verify the sender or source through a separate, trusted channel.",
        ]
    if c == "high_risk":
        return [
            "Avoid interacting, downloading, or installing.",
            "Do not click any embedded links or open attachments.",
            "Report to your security team for further investigation.",
        ]
    return [
        "Block the source immediately.",
        "Quarantine the affected file, account, or session.",
        "Escalate to the incident response team without delay.",
        "Preserve logs and artifacts for forensic investigation.",
    ]
