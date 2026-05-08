import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_browse_nonexistent_directory():
    nonexistent_path = "this_directory_should_not_exist_12345"
    url = f"{BASE_URL}/browse/{nonexistent_path}"

    try:
        response = requests.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        assert False, f"Request to browse nonexistent directory failed: {e}"

    assert response.status_code == 404, f"Expected 404 for nonexistent directory, got {response.status_code}"

test_browse_nonexistent_directory()