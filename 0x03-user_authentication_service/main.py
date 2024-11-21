#!/usr/bin/env python3

"""Module to test API endpoints using requests."""

import requests

BASE_URL = "http://127.0.0.1:5000"  # Update if your server runs on a different host/port


def register_user(email: str, password: str) -> None:
    """Tests user registration."""
    response = requests.post(f"{BASE_URL}/users", data={"email": email, "password": password})
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert response.json() == {"email": email, "message": "user created"}, f"Unexpected response: {response.json()}"


def log_in_wrong_password(email: str, password: str) -> None:
    """Tests login with wrong password."""
    response = requests.post(f"{BASE_URL}/sessions", data={"email": email, "password": password})
    assert response.status_code == 401, f"Expected 401, got {response.status_code}"


def log_in(email: str, password: str) -> str:
    """Tests login with correct password."""
    response = requests.post(f"{BASE_URL}/sessions", data={"email": email, "password": password})
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert "session_id" in response.cookies, "Missing session_id in cookies"
    return response.cookies["session_id"]


def profile_unlogged() -> None:
    """Tests accessing profile without being logged in."""
    response = requests.get(f"{BASE_URL}/profile")
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"


def profile_logged(session_id: str) -> None:
    """Tests accessing profile when logged in."""
    cookies = {"session_id": session_id}
    response = requests.get(f"{BASE_URL}/profile", cookies=cookies)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert "email" in response.json(), f"Unexpected response: {response.json()}"


def log_out(session_id: str) -> None:
    """Tests logging out."""
    cookies = {"session_id": session_id}
    response = requests.delete(f"{BASE_URL}/sessions", cookies=cookies)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"


def reset_password_token(email: str) -> str:
    """Tests generating a reset password token."""
    response = requests.post(f"{BASE_URL}/reset_password", data={"email": email})
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert "reset_token" in response.json(), f"Unexpected response: {response.json()}"
    return response.json()["reset_token"]


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Tests updating password using reset token."""
    response = requests.put(
        f"{BASE_URL}/reset_password",
        data={"email": email, "reset_token": reset_token, "new_password": new_password},
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert response.json() == {"email": email, "message": "Password updated"}, f"Unexpected response: {response.json()}"


# Test flow
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)

