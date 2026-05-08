import requests

def test_download_path_is_directory():
    base_url = "http://localhost:8000"
    directory_path = "test_dir_for_tc006"
    timeout = 30

    upload_url = f"{base_url}/upload"
    file_content = b"dummy content"
    files = {
        "files": ("dummy.txt", file_content),
    }
    data = {
        "path": directory_path
    }

    created_resource = False
    try:
        resp_upload = requests.post(upload_url, files=files, data=data, timeout=timeout)
        assert resp_upload.status_code == 200, f"Setup upload failed with status {resp_upload.status_code}"
        created_resource = True

        download_url = f"{base_url}/download/{directory_path}"
        resp_download = requests.get(download_url, timeout=timeout)

        assert resp_download.status_code == 400, f"Expected 400 for directory download, got {resp_download.status_code}"

    finally:
        pass

test_download_path_is_directory()
