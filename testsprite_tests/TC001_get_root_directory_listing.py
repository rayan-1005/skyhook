import requests

def test_get_root_directory_listing():
    base_url = "http://localhost:8000"
    url = f"{base_url}/"
    headers = {
        "Accept": "text/html"
    }
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        content_type = response.headers.get("Content-Type", "")
        assert "text/html" in content_type, f"Expected 'text/html' in Content-Type, got '{content_type}'"
        assert len(response.text) > 0, "Expected non-empty HTML content"
    except requests.RequestException as e:
        assert False, f"Request failed with exception: {e}"

test_get_root_directory_listing()