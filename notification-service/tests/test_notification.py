import logging

valid_request = {
    "email": "user@example.com",
    "subject": "ECWF OTP Verification",
    "body": "Your verification code is 123456. It expires in 5 minutes.",
    "purpose": "registration",
}


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "healthy"}


def test_send_otp_requires_authorization(client):
    resp = client.post("/send-otp", json=valid_request)
    assert resp.status_code == 401


def test_send_otp_wrong_key_rejected(client):
    resp = client.post(
        "/send-otp",
        json=valid_request,
        headers={"Authorization": "Bearer wrong-key"},
    )
    assert resp.status_code == 401


def test_send_otp_invalid_purpose_rejected(client, auth_header):
    payload = dict(valid_request, purpose="spam")
    resp = client.post("/send-otp", json=payload, headers=auth_header)
    assert resp.status_code == 422


def test_send_otp_missing_fields_rejected(client, auth_header):
    payload = {"email": "user@example.com"}
    resp = client.post("/send-otp", json=payload, headers=auth_header)
    assert resp.status_code == 422


def test_send_otp_reports_disabled_config(client, auth_header):
    resp = client.post("/send-otp", json=valid_request, headers=auth_header)
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"].lower()


def test_send_otp_success(client, auth_header, monkeypatch):
    import app.main as notification_main

    captured = {}

    def fake_send_email(to_email, subject, body):
        captured.update(to_email=to_email, subject=subject, body=body)

    monkeypatch.setattr(notification_main, "send_email", fake_send_email)

    resp = client.post("/send-otp", json=valid_request, headers=auth_header)
    assert resp.status_code == 200
    assert captured["to_email"] == "user@example.com"
    assert captured["subject"] == "ECWF OTP Verification"
    assert "123456" in captured["body"]
    data = resp.json()
    assert data["message"] == "OTP email accepted for delivery"
    assert data["email"] == "user@example.com"


def test_send_otp_smtp_failure(client, auth_header, monkeypatch):
    import app.main as notification_main
    from app.emailer import EmailDeliveryError

    def failing_send_email(to_email, subject, body):
        raise EmailDeliveryError("SMTP delivery failed")

    monkeypatch.setattr(notification_main, "send_email", failing_send_email)

    resp = client.post("/send-otp", json=valid_request, headers=auth_header)
    assert resp.status_code == 502


def test_send_otp_success_never_logs_otp(client, auth_header, monkeypatch, caplog):
    import app.main as notification_main

    monkeypatch.setattr(
        notification_main,
        "send_email",
        lambda to_email, subject, body: None,
    )

    with caplog.at_level(logging.INFO):
        resp = client.post("/send-otp", json=valid_request, headers=auth_header)
    assert resp.status_code == 200
    assert "123456" not in caplog.text


def test_send_otp_failure_never_logs_otp(client, auth_header, monkeypatch, caplog):
    import app.main as notification_main
    from app.emailer import EmailDeliveryError

    def failing_send_email(to_email, subject, body):
        raise EmailDeliveryError("SMTP delivery failed")

    monkeypatch.setattr(notification_main, "send_email", failing_send_email)

    with caplog.at_level(logging.WARNING):
        resp = client.post("/send-otp", json=valid_request, headers=auth_header)
    assert resp.status_code == 502
    assert "123456" not in caplog.text
    assert "ecwf-local-internal-2026" not in caplog.text