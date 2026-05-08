import requests
from io import BytesIO

BASE_URL = "http://localhost:8000"

def test_upload_files_success():
    url = f"{BASE_URL}/upload"
    # Prepare two example files to upload
    files = [
        ('files', ('testfile1.txt', BytesIO(b'This is test file 1 content'), 'text/plain')),
        ('files', ('testfile2.txt', BytesIO(b'Second test file content'), 'text/plain')),
    ]
    # Optional valid path to upload into
    data = {
        'path': 'uploads'
    }

    try:
        response = requests.post(url, files=files, data=data, timeout=30)
        assert response.status_code == 200, f"Expected status code 200 but got {response.status_code}"
        json_resp = response.json()
        assert "saved_files" in json_resp, "Response JSON missing 'saved_files' key"
        saved_files = json_resp["saved_files"]
        assert isinstance(saved_files, list), "Saved files info is not a list"
        for f in saved_files:
            assert isinstance(f, str), "Saved file entry is not a string"
        assert 'testfile1.txt' in saved_files, "testfile1.txt not found in saved files response"
        assert 'testfile2.txt' in saved_files, "testfile2.txt not found in saved files response"
    except requests.RequestException as e:
        assert False, f"RequestException during upload: {e}"

test_upload_files_success()
