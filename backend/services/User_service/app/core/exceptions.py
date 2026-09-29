class ServiceError(Exception):
    """Base class for domain errors raised by the User Service."""

    status_code: int = 500
    default_detail: str = "Unexpected server error"

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail or self.default_detail
        super().__init__(self.detail)


class UserNotFoundError(ServiceError):
    status_code = 404
    default_detail = "User not found"


class UserConflictError(ServiceError):
    status_code = 409
    default_detail = "User already exists"


class PermissionDeniedError(ServiceError):
    status_code = 403
    default_detail = "Insufficient permissions"


class AuthenticationError(ServiceError):
    status_code = 401
    default_detail = "Not authenticated"


class InternalApiDisabledError(ServiceError):
    status_code = 503
    default_detail = "Internal API is disabled"


class DatabaseOperationError(ServiceError):
    status_code = 503
    default_detail = "Database operation failed"
