import requests
import os

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_download_file_success():
    upload_url = f"{BASE_URL}/upload"
    download_url_prefix = f"{BASE_URL}/download/"
    test_filename = "testfile_tc005.txt"
    test_content = b"Test file content for TC005 download."

    files = {
        "files": (test_filename, test_content),
    }
    resp_upload = requests.post(upload_url, files=files, timeout=TIMEOUT)
    assert resp_upload.status_code == 200, f"File upload failed with status {resp_upload.status_code}"

    try:
        # Download the uploaded file
        resp_download = requests.get(f"{download_url_prefix}{test_filename}", timeout=TIMEOUT)
        assert resp_download.status_code == 200, f"Expected status 200 but got {resp_download.status_code}"
        # Verify content matches the uploaded content
        assert resp_download.content == test_content, "Downloaded file content does not match uploaded content"
        # Verify Content-Disposition header if present should signal file attachment with correct filename
        content_disp = resp_download.headers.get("Content-Disposition")
        if content_disp is not None:
            assert test_filename in content_disp, "Content-Disposition header filename incorrect"
    finally:
        # Cleanup: delete the uploaded test file
        pass

test_download_file_success()
