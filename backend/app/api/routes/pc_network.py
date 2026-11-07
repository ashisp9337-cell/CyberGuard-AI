"""(6 Nov) Live PC network monitor: this computer's open ports and live connections, read-only.
Administrator only - it shows the state of the computer CyberGuard runs on. Nothing is stored."""
from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.core.dependencies import require_admin
from app.core.rate_limit import limiter
from app.db.database import get_db
from app.db.models import IOC, User
from app.services import pc_network

router = APIRouter(prefix="/api/pc-network", tags=["pc-network"])


@router.get("")
@limiter.limit("30/minute")
async def pc_network_snapshot(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    flagged = {v for (v,) in db.query(IOC.value).filter(IOC.user_id == user.id, IOC.ioc_type == "ip").limit(5000)}
    return await run_in_threadpool(pc_network.snapshot, flagged)
