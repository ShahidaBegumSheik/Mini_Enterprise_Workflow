from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=255)
    description: str | None = None
    email: str | None = Field(default=None, max_length=255)
    phone: str | None = Field(default=None, max_length=50)
    website: HttpUrl | None = None
    address: str | None = None
    logo_url: HttpUrl | None = None
    timezone: str = Field(default="UTC", max_length=100)


class OrganizationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    description: str | None = None
    email: str | None = Field(default=None, max_length=255)
    phone: str | None = Field(default=None, max_length=50)
    website: HttpUrl | None = None
    address: str | None = None
    logo_url: HttpUrl | None = None
    timezone: str | None = Field(default=None, max_length=100)


class OrganizationSettingsUpdate(BaseModel):
    timezone: str | None = Field(default=None, max_length=100)
    is_active: bool | None = None


class OrganizationResponse(BaseModel):
    id: int
    name: str
    slug: str
    description: str | None
    email: str | None
    phone: str | None
    website: str | None
    address: str | None
    logo_url: str | None
    timezone: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)