"""
CYBERGUARD Email Intelligence Pipeline.

One email in -> one rich EmailEvent -> enrichment -> every relevant detector
(phishing, impersonation, URL, QR, attachments, account-takeover signals)
-> one fused verdict.

Entry point: app.email_pipeline.orchestrator.analyze_email()
"""
from app.email_pipeline.orchestrator import analyze_email  # noqa: F401
