from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.database import get_db
from app.db.models import KnownContact, User
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
def create_contact(body: ContactCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
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
    db.commit()
    db.refresh(contact)
    return _to_out(contact)


@router.put("/{contact_id}")
def update_contact(contact_id: str, body: ContactUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
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
    db.commit()
    db.refresh(contact)
    return _to_out(contact)


@router.delete("/{contact_id}", status_code=204)
def delete_contact(contact_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    contact = db.query(KnownContact).filter(KnownContact.id == contact_id, KnownContact.user_id == user.id).first()
    if not contact:
        raise HTTPException(status_code=404, detail={"error": {"code": "CONTACT_NOT_FOUND", "message": "Contact not found."}})
    db.delete(contact)
    db.commit()
    return None