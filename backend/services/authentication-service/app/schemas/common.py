from pydantic import BaseModel


class MessageResponse(BaseModel):
    message: str
    remaining_attempts: int | None = None
    resend_count: int | None = None
    expires_in: int | None = None


class SentimentResponse(BaseModel):
    message: str