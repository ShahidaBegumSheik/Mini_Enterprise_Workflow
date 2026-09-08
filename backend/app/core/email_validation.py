from dataclasses import dataclass


PERSONAL_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
}

PUBLIC_EMAIL_DOMAINS = PERSONAL_EMAIL_DOMAINS | {
    "aol.com",
    "protonmail.com",
    "proton.me",
    "mail.com",
    "zoho.com",
    "outlook.com",
}


@dataclass(frozen=True)
class EmailDomainInfo:
    domain: str
    is_personal: bool
    is_public: bool


def _extract_domain(email: str) -> str | None:
    if not email:
        return None
    parts = email.rsplit("@", 1)
    if len(parts) != 2 or not parts[1]:
        return None
    return parts[1].strip().lower()


def domain_info(email: str) -> EmailDomainInfo | None:
    domain = _extract_domain(email)
    if not domain:
        return None
    return EmailDomainInfo(
        domain=domain,
        is_personal=domain in PERSONAL_EMAIL_DOMAINS,
        is_public=domain in PUBLIC_EMAIL_DOMAINS,
    )


def is_personal_email(email: str) -> bool:
    info = domain_info(email)
    return bool(info and info.is_personal)


def is_business_email(email: str) -> bool:
    info = domain_info(email)
    return bool(info and not info.is_public)
