import requests

BASE_URL = "http://localhost:8000"


def test_download_file_not_found():
    missing_file_path = "nonexistent/path/to/missing_file.txt"
    url = f"{BASE_URL}/download/{missing_file_path}"

    try:
        response = requests.get(url, timeout=30)
    except requests.RequestException as e:
        assert False, f"Request failed: {e}"

    assert response.status_code == 404, f"Expected status code 404, got {response.status_code}"
    # Optionally, check text or json message if server provides any
    # but it is not specified, so checking status code is sufficient


test_download_file_not_found()