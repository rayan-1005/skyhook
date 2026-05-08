import requests

def test_browse_subdirectory_listing():
    base_url = "http://127.0.0.1:8000"
    # Define a valid subdirectory to browse; using 'documents' as example from the PRD user flows
    subdirectory_path = "documents"
    url = f"{base_url}/browse/{subdirectory_path}"

    try:
        response = requests.get(url, timeout=30)
    except requests.RequestException as e:
        assert False, f"Request to browse subdirectory failed: {e}"

    assert response.status_code == 200, f"Expected status code 200 but got {response.status_code}"
    content_type = response.headers.get("Content-Type", "")
    # The response should be HTML according to PRD
    assert "text/html" in content_type.lower(), f"Expected Content-Type to include 'text/html' but got {content_type}"
    # Verify response body contains HTML tags typical for directory listing
    assert response.text.strip().startswith("<!DOCTYPE html>") or "<html" in response.text.lower(), \
        "Response body does not appear to be a valid HTML page."

test_browse_subdirectory_listing()