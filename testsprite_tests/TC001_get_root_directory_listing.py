import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_get_root_directory_listing():
    url = f"{BASE_URL}/"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        content_type = response.headers.get("Content-Type", "")
        assert "text/html" in content_type.lower(), f"Expected Content-Type to include 'text/html', got '{content_type}'"
        assert len(response.text) > 0, "Response HTML content is empty"
    except requests.RequestException as e:
        assert False, f"Request to {url} failed: {e}"

test_get_root_directory_listing()