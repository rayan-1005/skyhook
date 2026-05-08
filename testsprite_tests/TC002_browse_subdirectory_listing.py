import requests

def test_browse_subdirectory_listing():
    base_url = "http://127.0.0.1:8000"
    subdirectory = "documents"
    url = f"{base_url}/browse/{subdirectory}"
    try:
        response = requests.get(url, timeout=30)
        assert response.status_code == 200, f"Expected 200 but got {response.status_code}"
        content_type = response.headers.get("Content-Type", "")
        assert "text/html" in content_type.lower(), f"Expected HTML content but got {content_type}"
        assert subdirectory in response.text, "Subdirectory name not found in response HTML"
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

test_browse_subdirectory_listing()