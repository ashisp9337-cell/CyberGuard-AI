"""(6 Nov) Live PC network monitor: this computer's open ports and live connections.
Administrator only - it shows the state of the computer CyberGuard runs on. Nothing is stored.
(10 Nov) Actions: block a port / an address (Windows Firewall, undoable), close a connection, end a program - each
one an explicit administrator click, written to the activity log (app/services/pc_actions.py)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.dependencies import require_admin
from app.core.rate_limit import limiter
from app.db.database import get_db
from app.db.models import IOC, User
from app.services import audit, pc_actions, pc_network

router = APIRouter(prefix="/api/pc-network", tags=["pc-network"])


@router.get("")
@limiter.limit("30/minute")
async def pc_network_snapshot(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    flagged = {v for (v,) in db.query(IOC.value).filter(IOC.user_id == user.id, IOC.ioc_type == "ip").limit(5000)}
    return await run_in_threadpool(pc_network.snapshot, flagged)


class BlockPortBody(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="TCP", pattern="^(TCP|UDP)$")


class BlockAddressBody(BaseModel):
    address: str = Field(min_length=2, max_length=64)


class UnblockBody(BaseModel):
    name: str = Field(min_length=5, max_length=200)


class CloseBody(BaseModel):
    localAddress: str = Field(max_length=64)
    localPort: int = Field(ge=1, le=65535)
    remoteAddress: str = Field(max_length=64)
    remotePort: int = Field(ge=1, le=65535)


class EndBody(BaseModel):
    pid: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=260)


async def _act(request, db, user, action: str, target: str, fn, *args):
    try:
        result = await run_in_threadpool(fn, *args)
    except pc_actions.ActionError as e:
        audit.log(db, action=action, user=user, request=request, target=target, detail={"error": e.message[:300]},
                  success=False, commit=True)
        raise HTTPException(status_code=e.status, detail={"error": {"code": "PC_ACTION_FAILED", "message": e.message}})
    audit.log(db, action=action, user=user, request=request, target=target, detail={"message": result["message"][:300]},
              commit=True)
    return result


@router.post("/block-port")
@limiter.limit("20/minute")
async def block_port(request: Request, body: BlockPortBody, user: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    return await _act(request, db, user, "pc.block_port", f"{body.protocol} {body.port}",
                      pc_actions.block_port, body.port, body.protocol)


@router.post("/block-address")
@limiter.limit("20/minute")
async def block_address(request: Request, body: BlockAddressBody, user: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    return await _act(request, db, user, "pc.block_address", body.address, pc_actions.block_address, body.address)


@router.post("/unblock")
@limiter.limit("20/minute")
async def unblock(request: Request, body: UnblockBody, user: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    return await _act(request, db, user, "pc.unblock", body.name, pc_actions.unblock, body.name)


@router.post("/close-connection")
@limiter.limit("30/minute")
async def close_connection(request: Request, body: CloseBody, user: User = Depends(require_admin),
                           db: Session = Depends(get_db)):
    target = f"{body.localAddress}:{body.localPort} -> {body.remoteAddress}:{body.remotePort}"
    return await _act(request, db, user, "pc.close_connection", target, pc_actions.close_connection,
                      body.localAddress, body.localPort, body.remoteAddress, body.remotePort)


@router.post("/end-process")
@limiter.limit("10/minute")
async def end_process(request: Request, body: EndBody, user: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    return await _act(request, db, user, "pc.end_process", f"{body.name} (pid {body.pid})",
                      pc_actions.end_process, body.pid, body.name)


class CutOffBody(BaseModel):
    pid: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=260)
    remoteAddress: str = Field(min_length=2, max_length=64)
    localAddress: str = Field(default="", max_length=64)
    localPort: int = Field(default=0, ge=0, le=65535)
    remotePort: int = Field(default=0, ge=0, le=65535)


@router.post("/cut-off")
@limiter.limit("20/minute")
async def cut_off(request: Request, body: CutOffBody, user: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """(10 Nov) Cut one program off from one address: firewall rule for that program + drop the live connection."""
    return await _act(request, db, user, "pc.cut_off", f"{body.name} (pid {body.pid}) -> {body.remoteAddress}",
                      pc_actions.cut_off, body.pid, body.name, body.remoteAddress, body.localAddress,
                      body.localPort, body.remotePort)
