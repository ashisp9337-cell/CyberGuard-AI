def test_register_success(client):
    r = client.post("/api/auth/register", json={"name": "Alice", "email": "alice@example.com", "password": "GoodPass123"})
    assert r.status_code == 201
    assert r.json()["user"]["email"] == "alice@example.com"


def test_register_duplicate_email(client):
    body = {"name": "Alice", "email": "alice@example.com", "password": "GoodPass123"}
    client.post("/api/auth/register", json=body)
    r = client.post("/api/auth/register", json=body)
    assert r.status_code == 409


def test_register_weak_password(client):
    r = client.post("/api/auth/register", json={"name": "Alice", "email": "a2@example.com", "password": "weak"})
    assert r.status_code == 422


def test_login_success(client):
    client.post("/api/auth/register", json={"name": "Bob", "email": "bob@example.com", "password": "GoodPass123"})
    r = client.post("/api/auth/login", json={"email": "bob@example.com", "password": "GoodPass123"})
    assert r.status_code == 200


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={"name": "Bob", "email": "bob2@example.com", "password": "GoodPass123"})
    r = client.post("/api/auth/login", json={"email": "bob2@example.com", "password": "WrongPass123"})
    assert r.status_code == 401


def test_me_requires_auth(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_me_after_login(auth_client):
    r = auth_client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["email"] == auth_client._test_email


def test_logout_clears_session(auth_client):
    auth_client.post("/api/auth/logout")
    r = auth_client.get("/api/auth/me")
    assert r.status_code == 401


def test_forgot_password_dev_token(client):
    client.post("/api/auth/register", json={"name": "Carl", "email": "carl@example.com", "password": "GoodPass123"})
    r = client.post("/api/auth/forgot-password", json={"email": "carl@example.com"})
    assert r.status_code == 200
    assert "devResetToken" in r.json()


def test_forgot_password_unknown_email_same_response_shape(client):
    r = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert r.status_code == 200
    assert "devResetToken" not in r.json()


def test_reset_password_flow(client):
    client.post("/api/auth/register", json={"name": "Dana", "email": "dana@example.com", "password": "OldPass123"})
    r = client.post("/api/auth/forgot-password", json={"email": "dana@example.com"})
    token = r.json()["devResetToken"]
    r2 = client.post("/api/auth/reset-password", json={"token": token, "newPassword": "NewPass456"})
    assert r2.status_code == 200
    r3 = client.post("/api/auth/login", json={"email": "dana@example.com", "password": "NewPass456"})
    assert r3.status_code == 200


def test_reset_password_invalid_token(client):
    r = client.post("/api/auth/reset-password", json={"token": "not-a-real-token", "newPassword": "NewPass456"})
    assert r.status_code == 400
