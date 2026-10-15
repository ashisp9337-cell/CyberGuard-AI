from pydantic import BaseModel, Field


class ContactCreate(BaseModel):
    displayName: str = Field(..., min_length=1, max_length=200)
    roleLabel: str = Field("", max_length=120)
    authorizedEmail: str = Field("", max_length=254)
    authorizedDomain: str = Field("", max_length=253)
    typicalHoursStart: int = Field(0, ge=0, le=23)
    typicalHoursEnd: int = Field(23, ge=0, le=23)
    highRiskRequestsAllowed: bool = False
    notes: str = Field("", max_length=2000)


class ContactUpdate(BaseModel):
    displayName: str | None = Field(None, min_length=1, max_length=200)
    roleLabel: str | None = Field(None, max_length=120)
    authorizedEmail: str | None = Field(None, max_length=254)
    authorizedDomain: str | None = Field(None, max_length=253)
    typicalHoursStart: int | None = Field(None, ge=0, le=23)
    typicalHoursEnd: int | None = Field(None, ge=0, le=23)
    highRiskRequestsAllowed: bool | None = None
    notes: str | None = Field(None, max_length=2000)