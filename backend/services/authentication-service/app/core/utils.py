from datetime import datetime, timezone


def utcnow() -> datetime:
    """Naive UTC now, safe to store in DATETIME columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)