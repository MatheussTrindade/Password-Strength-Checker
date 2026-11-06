def test_index_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers


def test_check_returns_analysis(client):
    response = client.post("/check", json={"password": "Senha@2024"})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = response.get_json()
    assert {"score", "label", "entropy", "patterns", "crack_times", "pwned", "feedback"} <= body.keys()


def test_check_rejects_invalid_payloads(client):
    assert client.post("/check", json={}).status_code == 400
    assert client.post("/check", json={"password": 123}).status_code == 400
    assert client.post("/check", data="not json").status_code == 400
    assert client.post("/check", json={"password": "a" * 257}).status_code == 400
