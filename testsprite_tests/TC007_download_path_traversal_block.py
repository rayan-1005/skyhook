import requests
import urllib.parse

def test_download_path_traversal_block():
    base_url = "http://localhost:8000"
    traversal_path = "../../secret.txt"
    encoded_path = urllib.parse.quote(traversal_path, safe='')
    url = f"{base_url}/download/{encoded_path}"

    try:
        response = requests.get(url, timeout=30)
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

    assert response.status_code == 403, f"Expected status code 403, got {response.status_code}"

test_download_path_traversal_block()