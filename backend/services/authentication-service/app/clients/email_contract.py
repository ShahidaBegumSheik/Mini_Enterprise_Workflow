from typing import Any, Protocol


class EmailServiceContract(Protocol):
    async def send_email_notification(
        self,
        *,
        recipient_email: str,
        event_type: str,
        template_variables: dict[str, Any],
    ) -> None:
        ...
