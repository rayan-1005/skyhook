import requests
import os

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_download_file_success():
    # Step 1: Upload a file to have a valid file path to download
    upload_url = f"{BASE_URL}/upload"
    file_content = b"Test content for download file success case."
    files = {
        "files": ("testfile.txt", file_content, "text/plain")
    }

    uploaded_file_path = None
    try:
        # Upload the file to root directory (default)
        upload_response = requests.post(upload_url, files=files, timeout=TIMEOUT)
        assert upload_response.status_code == 200, f"Upload failed with status code {upload_response.status_code}"
        json_response = upload_response.json()
        # Adjust assertion to check presence of 'filenames' key and confirm uploaded file
        assert 'filenames' in json_response and "testfile.txt" in json_response['filenames'], "Uploaded file not confirmed in response"
        # Store the uploaded file relative path to download
        uploaded_file_path = "testfile.txt"

        # Step 2: Download the uploaded file
        download_url = f"{BASE_URL}/download/{uploaded_file_path}"
        download_response = requests.get(download_url, timeout=TIMEOUT)
        assert download_response.status_code == 200, f"Download failed with status code {download_response.status_code}"
        # The content returned should match the uploaded content
        assert download_response.content == file_content, "Downloaded file content does not match uploaded content"
        # Content-Type header should indicate a file type, e.g. text/plain
        content_type = download_response.headers.get("Content-Type", "")
        assert content_type.startswith("text/") or content_type == "application/octet-stream", f"Unexpected content type: {content_type}"

    finally:
        # Cleanup: Delete the uploaded file if possible
        if uploaded_file_path:
            delete_url = f"{BASE_URL}/upload"
            # The PRD does not specify delete endpoint, so skip if not supported
            pass

test_download_file_success()
