import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_health_check_endpoint():
    url = f"{BASE_URL}/health"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

    assert response.status_code == 200, f"Expected status code 200 but got {response.status_code}"
    try:
        data = response.json()
    except ValueError:
        assert False, "Response is not valid JSON"

    assert "status" in data, "Response JSON does not contain 'status' field"
    assert isinstance(data["status"], str), "'status' field is not a string"
    assert "version" in data, "Response JSON does not contain 'version' field"
    assert isinstance(data["version"], str), "'version' field is not a string"

test_health_check_endpoint()