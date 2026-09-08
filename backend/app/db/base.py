from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.user import User
from app.models.tenant import Tenant
from app.models.otp_verification import OTPVerification
from app.models.refresh_token import RefreshToken