import requests

def test_browse_path_traversal_block():
    base_url = "http://localhost:8000"
    path_traversal = "../../etc/passwd"
    url = f"{base_url}/browse/{path_traversal}"
    headers = {
        "Accept": "text/html"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

    assert response.status_code == 403, f"Expected status code 403, got {response.status_code}"

test_browse_path_traversal_block()