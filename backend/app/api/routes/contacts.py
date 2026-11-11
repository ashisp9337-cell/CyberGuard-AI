from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import KnownContact, User
from app.core.rate_limit import limiter
from app.services import audit, contact_import
from app.schemas.contacts import ContactCreate, ContactUpdate

router = APIRouter(prefix="/api/contacts", tags=["contacts"])


def _to_out(c: KnownContact) -> dict:
    return {
        "id": c.id, "displayName": c.display_name, "roleLabel": c.role_label,
        "authorizedEmail": c.authorized_email, "authorizedDomain": c.authorized_domain,
        "typicalHoursStart": c.typical_hours_start, "typicalHoursEnd": c.typical_hours_end,
        "highRiskRequestsAllowed": c.high_risk_requests_allowed, "notes": c.notes,
        "createdAt": c.created_at.isoformat() if c.created_at else "",
        "updatedAt": c.updated_at.isoformat() if c.updated_at else "",
    }


@router.get("")
def list_contacts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(KnownContact).filter(KnownContact.user_id == user.id).order_by(KnownContact.display_name).all()
    return [_to_out(r) for r in rows]


@router.post("", status_code=201)
def create_contact(body: ContactCreate, request: Request, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    contact = KnownContact(
        user_id=user.id,
        display_name=body.displayName.strip(),
        role_label=body.roleLabel.strip(),
        authorized_email=body.authorizedEmail.strip().lower(),
        authorized_domain=(body.authorizedDomain or body.authorizedEmail.split("@")[-1] if "@" in body.authorizedEmail else body.authorizedDomain).strip().lower(),
        typical_hours_start=body.typicalHoursStart,
        typical_hours_end=body.typicalHoursEnd,
        high_risk_requests_allowed=body.highRiskRequestsAllowed,
        notes=body.notes.strip(),
    )
    db.add(contact)
    audit.log(db, action="contact.create", user=user, request=request, target=contact.display_name,
              detail={"email": contact.authorized_email, "domain": contact.authorized_domain})
    db.commit()
    db.refresh(contact)
    return _to_out(contact)


MAX_CONTACTS_PER_USER = 5000


@router.post("/import")
@limiter.limit("6/minute")
async def import_contacts(request: Request, file: UploadFile = File(...), user: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    """(11 Nov) Import names (+ first e-mail) from a phone / Google / Outlook contacts export (.vcf or .csv). Phone
    numbers and everything else in the file are ignored; the file is read in memory and never stored."""
    raw = await file.read(contact_import.MAX_BYTES + 1)
    try:
        kind, found, no_name = contact_import.parse(raw)
    except contact_import.ImportError_ as e:
        raise HTTPException(status_code=400, detail={"error": {"code": "CONTACT_IMPORT_FAILED", "message": str(e)}})
    existing = db.query(KnownContact).filter(KnownContact.user_id == user.id).all()
    have = {(c.display_name.strip().lower(), (c.authorized_email or "").lower()) for c in existing}
    have_names = {k[0] for k in have}
    room = MAX_CONTACTS_PER_USER - len(existing)
    added = duplicates = over = 0
    for c in found:
        key = (c["name"].lower(), c["email"])
        # the same name already saved (with or without an e-mail) is the same person: never a second copy
        if key in have or (key[0] in have_names and not c["email"]):
            duplicates += 1
            continue
        if added >= room:
            over += 1
            continue
        db.add(KnownContact(user_id=user.id, display_name=c["name"], role_label="", authorized_email=c["email"],
                            authorized_domain=c["email"].split("@")[-1] if c["email"] else "",
                            notes="Imported from a contacts file"))
        have.add(key)
        have_names.add(key[0])
        added += 1
    # the activity log records how many - never the names
    audit.log(db, action="contact.import", user=user, request=request, target=kind,
              detail={"imported": added, "duplicates": duplicates, "withoutName": no_name, "overLimit": over})
    db.commit()
    return {"format": kind, "imported": added, "duplicates": duplicates, "withoutName": no_name, "overLimit": over,
            "total": len(existing) + added}


@router.delete("", status_code=200)
def delete_all_contacts(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """(11 Nov) Remove every saved contact of THIS user (e.g. after importing the wrong file)."""
    n = db.query(KnownContact).filter(KnownContact.user_id == user.id).delete(synchronize_session=False)
    audit.log(db, action="contact.delete_all", user=user, request=request, target="all", detail={"removed": n})
    db.commit()
    return {"removed": n}


@router.put("/{contact_id}")
def update_contact(contact_id: str, body: ContactUpdate, request: Request, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    contact = db.query(KnownContact).filter(KnownContact.id == contact_id, KnownContact.user_id == user.id).first()
    if not contact:
        raise HTTPException(status_code=404, detail={"error": {"code": "CONTACT_NOT_FOUND", "message": "Contact not found."}})
    if body.displayName is not None:
        contact.display_name = body.displayName.strip()
    if body.roleLabel is not None:
        contact.role_label = body.roleLabel.strip()
    if body.authorizedEmail is not None:
        contact.authorized_email = body.authorizedEmail.strip().lower()
    if body.authorizedDomain is not None:
        contact.authorized_domain = body.authorizedDomain.strip().lower()
    if body.typicalHoursStart is not None:
        contact.typical_hours_start = body.typicalHoursStart
    if body.typicalHoursEnd is not None:
        contact.typical_hours_end = body.typicalHoursEnd
    if body.highRiskRequestsAllowed is not None:
        contact.high_risk_requests_allowed = body.highRiskRequestsAllowed
    if body.notes is not None:
        contact.notes = body.notes.strip()
    audit.log(db, action="contact.update", user=user, request=request, target=contact.display_name,
              detail={k: v for k, v in body.model_dump(exclude_none=True).items() if k != "notes"})
    db.commit()
    db.refresh(contact)
    return _to_out(contact)


@router.delete("/{contact_id}", status_code=204)
def delete_contact(contact_id: str, request: Request, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    contact = db.query(KnownContact).filter(KnownContact.id == contact_id, KnownContact.user_id == user.id).first()
    if not contact:
        raise HTTPException(status_code=404, detail={"error": {"code": "CONTACT_NOT_FOUND", "message": "Contact not found."}})
    audit.log(db, action="contact.delete", user=user, request=request, target=contact.display_name)
    db.delete(contact)
    db.commit()
    return None