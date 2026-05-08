import requests

def test_download_file_not_found():
    base_url = "http://localhost:8000"
    missing_file_path = "nonexistent_file_1234567890.txt"
    url = f"{base_url}/download/{missing_file_path}"

    try:
        response = requests.get(url, timeout=30)
    except requests.RequestException as e:
        assert False, f"Request to {url} failed with exception: {e}"

    assert response.status_code == 404, f"Expected 404 status code for missing file, got {response.status_code} instead."

test_download_file_not_found()