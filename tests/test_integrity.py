import requests
import hashlib

# This test assumes you run flask locally on port 5000.
BASE = "http://127.0.0.1:5000"

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

def test_roundtrip():
    filename = "tests/sample.txt"
    # create sample
    with open(filename, "wb") as f:
        f.write(b"Hello encrypted world!\nThis is a sample file.\n")

    # upload via multipart
    with open(filename, "rb") as f:
        files = {"file": ("sample.txt", f)}
        r = requests.post(f"{BASE}/upload", files=files)
    print("Upload status:", r.status_code)
    assert r.status_code in (200, 302)  # redirect allowed

    # fetch index to get stored name (rough parse)
    r = requests.get(BASE)
    assert r.status_code == 200
    body = r.text
    # hack: find first occurrence of an underscore followed by sample.txt
    idx = body.find("_sample.txt")
    assert idx != -1
    # find the stored name around it (get preceding token)
    # back to start of word
    start = body.rfind(">", 0, idx) + 1
    end = body.find("<", idx)
    stored_name = body[start:end].strip()
    print("Found stored name:", stored_name)

    # download decrypted file
    r = requests.get(f"{BASE}/download/{stored_name}")
    assert r.status_code == 200
    downloaded = r.content

    # compare sha
    with open(filename, "rb") as f:
        orig = f.read()
    print("orig sha:", sha256_bytes(orig))
    print("download sha:", sha256_bytes(downloaded))
    assert sha256_bytes(orig) == sha256_bytes(downloaded)
    print("Integrity test passed")

if __name__ == "__main__":
    test_roundtrip()
