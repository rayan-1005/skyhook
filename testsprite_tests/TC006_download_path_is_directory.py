import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_download_path_is_directory():
    # Use a directory name expected to be a directory
    dir_name = "uploads"
    url = f"{BASE_URL}/download/{dir_name}/"
    response = requests.get(url, timeout=TIMEOUT)

    # Assert that status code is 400 indicating path is not a file
    assert response.status_code == 400, f"Expected status code 400 but got {response.status_code}. This might mean the directory '{dir_name}' does not exist or the API behavior is different."

test_download_path_is_directory()
