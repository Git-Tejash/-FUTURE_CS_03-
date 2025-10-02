import os
from flask import Flask, request, redirect, url_for, send_file, render_template, flash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from pathlib import Path
from dotenv import load_dotenv
from io import BytesIO

# Load .env (optional)
load_dotenv()

# Configuration
UPLOAD_FOLDER = Path("storage")
UPLOAD_FOLDER.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = None  # allow all types; enforce in UI or change this variable
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB limit (adjust as needed)

# Key management (basic): read 32-byte key from env var AES_KEY (base64 hex or raw)
# We'll expect a hex string of 64 hex chars (32 bytes) for simplicity.
AES_KEY_HEX = os.getenv("AES_KEY_HEX")
if not AES_KEY_HEX:
    # For development convenience only: generate temporary key and print a warning.
    # **Do not** use this in production.
    temp_key = secrets.token_bytes(32)
    AES_KEY_HEX = temp_key.hex()
    print("WARNING: No AES_KEY_HEX found in environment. Using an auto-generated key (development only).")
    print("Set AES_KEY_HEX environment variable (64 hex chars) for production.")
KEY = bytes.fromhex(AES_KEY_HEX)
if len(KEY) != 32:
    raise ValueError("AES_KEY_HEX must be 64 hex chars (32 bytes) for AES-256.")

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def allowed_file(filename: str) -> bool:
    if not filename:
        return False
    # allow all by default. Restrict here if needed.
    return True


def encrypt_bytes(plain: bytes, key: bytes) -> bytes:
    """
    Encrypt bytes with AES-GCM.
    Stored format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    AESGCM returns ciphertext+tag, so we just prefix nonce.
    """
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
    ct = aesgcm.encrypt(nonce, plain, associated_data=None)
    return nonce + ct


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """
    Reverse of encrypt_bytes. Expect blob = nonce || ciphertext_and_tag.
    """
    if len(blob) < 12 + 16:
        raise ValueError("Ciphertext too short.")
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)


@app.route("/", methods=["GET"])
def index():
    files = []
    for p in sorted(Path(app.config["UPLOAD_FOLDER"]).iterdir()):
        if p.is_file():
            files.append({"name": p.name, "size": p.stat().st_size})
    return render_template("index.html", files=files)


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part")
        return redirect(url_for("index"))
    file = request.files["file"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("index"))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # read file bytes
        data = file.read()
        # encrypt
        encrypted = encrypt_bytes(data, KEY)
        # To avoid name collisions, include a random prefix (but keep original filename visible)
        storage_name = f"{secrets.token_hex(8)}_{filename}"
        out_path = Path(app.config["UPLOAD_FOLDER"]) / storage_name
        with open(out_path, "wb") as f:
            f.write(encrypted)
        flash(f"Uploaded and encrypted as {storage_name}")
        return redirect(url_for("index"))
    flash("File not allowed")
    return redirect(url_for("index"))


@app.route("/download/<stored_name>", methods=["GET"])
def download(stored_name):
    # sanitize: only allow files inside UPLOAD_FOLDER
    stored_path = Path(app.config["UPLOAD_FOLDER"]) / Path(stored_name).name
    if not stored_path.exists() or not stored_path.is_file():
        flash("File not found")
        return redirect(url_for("index"))
    # read encrypted bytes
    with open(stored_path, "rb") as f:
        blob = f.read()
    try:
        plain = decrypt_bytes(blob, KEY)
    except Exception as e:
        flash("Decryption failed: file corrupted or wrong key")
        return redirect(url_for("index"))
    # send as attachment; original filename after underscore
    # stored format: <rand>_<orig>
    orig = "_".join(stored_name.split("_")[1:]) or stored_name
    return send_file(BytesIO(plain), as_attachment=True, download_name=orig)


@app.route("/delete/<stored_name>", methods=["POST"])
def delete(stored_name):
    stored_path = Path(app.config["UPLOAD_FOLDER"]) / Path(stored_name).name
    if stored_path.exists():
        stored_path.unlink()
        flash("Deleted.")
    else:
        flash("Not found.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
