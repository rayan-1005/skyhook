import requests

def test_browse_path_traversal_block():
    base_url = "http://localhost:8000"
    malicious_path = "../../etc/passwd"
    url = f"{base_url}/browse/{malicious_path}"
    try:
        response = requests.get(url, timeout=30)
        assert response.status_code == 404, f"Expected status code 404, got {response.status_code}"
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

test_browse_path_traversal_block()