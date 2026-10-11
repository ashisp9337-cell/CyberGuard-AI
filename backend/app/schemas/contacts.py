from pydantic import BaseModel, Field


class ContactCreate(BaseModel):
    displayName: str = Field(..., min_length=1, max_length=200)
    roleLabel: str = ""
    authorizedEmail: str = ""
    authorizedDomain: str = ""
    typicalHoursStart: int = 0
    typicalHoursEnd: int = 23
    highRiskRequestsAllowed: bool = False
    notes: str = ""


class ContactUpdate(BaseModel):
    displayName: str | None = None
    roleLabel: str | None = None
    authorizedEmail: str | None = None
    authorizedDomain: str | None = None
    typicalHoursStart: int | None = None
    typicalHoursEnd: int | None = None
    highRiskRequestsAllowed: bool | None = None
    notes: str | None = None