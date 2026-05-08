import requests
import io

BASE_URL = "http://localhost:8000"

def test_upload_files_success():
    url = f"{BASE_URL}/upload"
    files = {
        "files": (
            "testfile1.txt",
            io.BytesIO(b"Hello, this is test file 1."),
            "text/plain"
        )
    }
    data = {
        "path": "uploads"
    }
    try:
        response = requests.post(url, files=files, data=data, timeout=30)
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        json_response = response.json()
        assert "files" in json_response or "saved_files" in json_response or "uploaded" in json_response, "Response JSON lacks confirmation of saved files"
    finally:
        # Cleanup the uploaded file if deletion endpoint or method is available.
        # Since no API for deletion is mentioned, skipping cleanup here.
        pass

test_upload_files_success()