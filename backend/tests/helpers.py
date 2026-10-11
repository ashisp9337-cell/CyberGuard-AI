"""Test helpers for the OTP sign-up / login flow.
In tests no email is configured, so the API returns the code as `devOtp` (development mode)."""


def register_user(client, body: dict):
    """Sign up through all three steps. Returns the final response (201, session cookie set)."""
    r1 = client.post("/api/auth/signup/start", json={"name": body["name"], "email": body["email"]})
    if r1.status_code != 200:
        return r1
    r2 = client.post("/api/auth/signup/verify", json={"challengeId": r1.json()["challengeId"], "code": r1.json()["devOtp"]})
    if r2.status_code != 200:
        return r2
    return client.post("/api/auth/signup/complete", json={"signupToken": r2.json()["signupToken"], "password": body["password"]})


def login_user(client, email: str, password: str, remember_me: bool = True):
    """Password step + OTP step. Returns the final response (200, session cookie set)."""
    r1 = client.post("/api/auth/login", json={"email": email, "password": password, "rememberMe": remember_me})
    if r1.status_code != 200:
        return r1
    return client.post("/api/auth/login/verify", json={"challengeId": r1.json()["challengeId"], "code": r1.json()["devOtp"]})
