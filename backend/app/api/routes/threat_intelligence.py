from fastapi import APIRouter, Depends, HTTPException, Query, Request
from app.core.dependencies import get_current_user
from app.core.rate_limit import limiter
from app.db.models import User
from app.services.threat_intelligence import lookup_url

router = APIRouter(prefix="/api/threat-intelligence", tags=["threat-intelligence"])


@router.get("/lookup")
@limiter.limit("10/minute")
async def lookup(request: Request, url: str = Query(..., max_length=2048), user: User = Depends(get_current_user)):
    """Sends the URL to external feeds (with this server's API keys), so it is rate-limited and must be http(s)."""
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail={"error": {"code": "INVALID_URL", "message": "Enter a full http:// or https:// link."}})
    return await lookup_url(url)
