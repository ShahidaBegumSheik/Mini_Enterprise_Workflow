"""REST client for the Notification Service (isolated, single source file).

The Authentication Service never implements notification business logic. It
only hands the Notification Service the recipient address, the event type and
the template variables; the Notification Service renders and delivers the
email, and owns any delivery infrastructure.

The raw OTP is passed inside ``template_variables`` because it IS the message
content, but it is never logged here, never persisted, and — like every other
field — is sent over the internal service network. Passwords and JWT tokens
are deliberately never part of a payload.
"""

from typing import Any

import httpx

from app.clients.contracts import (
    NTF_FORGOT_PASSWORD_OTP,
    NTF_INDIVIDUAL_REGISTRATION_OTP,
    NTF_ORGANIZATION_REGISTRATION_OTP,
    EmailServiceContract,
    ServiceCallError,
    ServiceResponseError,
)
from app.core.config import settings

NOTIFICATION_SERVICE = "notification-service"
NOTIFICATION_ENDPOINT = "/api/v1/internal/notifications"

__all__ = [
    "NOTIFICATION_SERVICE",
    "NotificationServiceClient",
    "NTF_INDIVIDUAL_REGISTRATION_OTP",
    "NTF_ORGANIZATION_REGISTRATION_OTP",
    "NTF_FORGOT_PASSWORD_OTP",
]


class NotificationServiceClient(EmailServiceContract):
    """HTTPX-based implementation of the Notification Service contract.

    Communication uses the shared ``httpx.AsyncClient``; the base URL, the
    internal API key and the timeout all come from configuration. Delivery is
    asynchronous from the caller's perspective (the client is ``async``) and
    uses the caller's own per-request timeout override when provided.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        base_url: str | None = None,
        internal_api_key: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.http = http
        self.base_url = (base_url or settings.notification_service_url).rstrip("/")
        self.internal_api_key = internal_api_key or settings.internal_api_key
        self.per_request_timeout = timeout
        # A single retry on a timeout is safe for OTP emails: the worst case
        # is the user receives the same OTP twice. Connection failures and
        # HTTP status errors are NOT retried (they are not transient in the
        # same way and would be louder down-stream).
        self.timeout_retries = 1

    def _headers(self) -> dict[str, str]:
        return {"X-Internal-API-Key": self.internal_api_key}

    def _request_timeout(self):
        if self.per_request_timeout is None:
            return None
        return httpx.Timeout(self.per_request_timeout)

    def _raise_for(self, response: httpx.Response) -> None:
        if response.status_code >= 400:
            raise ServiceCallError(
                service=NOTIFICATION_SERVICE,
                status_code=response.status_code,
                detail=response.text,
            )

    async def send_email_notification(
        self,
        *,
        recipient_email: str,
        event_type: str,
        template_variables: dict[str, Any],
    ) -> None:
        """Ask the Notification Service to send a templated event email.

        The payload is intentionally minimal: recipient address, event type
        and template variables. No passwords, no JWT tokens, no credentials.
        """
        payload: dict[str, Any] = {
            "recipient_email": recipient_email,
            "event_type": event_type,
            "template_variables": template_variables,
        }

        response: httpx.Response | None = None
        for attempt in range(self.timeout_retries + 1):
            try:
                response = await self.http.post(
                    f"{self.base_url}{NOTIFICATION_ENDPOINT}",
                    headers=self._headers(),
                    json=payload,
                    timeout=self._request_timeout(),
                )
                break
            except httpx.TimeoutException:
                if attempt >= self.timeout_retries:
                    raise
                continue

        if response is None:  # pragma: no cover - defensive
            raise ServiceResponseError(NOTIFICATION_SERVICE, "no response received")

        self._raise_for(response)
        # 2xx means the Notification Service accepted the event; delivery
        # details (rendering, SMTP) belong to it, not to this service.