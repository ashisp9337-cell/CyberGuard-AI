from fastapi import APIRouter, Depends, Query
from app.core.dependencies import get_current_user
from app.db.models import User
from app.services.threat_intelligence import lookup_url

router = APIRouter(prefix="/api/threat-intelligence", tags=["threat-intelligence"])


@router.get("/lookup")
async def lookup(url: str = Query(...), user: User = Depends(get_current_user)):
    return await lookup_url(url)
