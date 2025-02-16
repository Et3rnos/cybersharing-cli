import binascii
import datetime
import mimetypes
import os
from typing import List
import requests
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
import typer
from cybersharing.config import read_config
from cybersharing.encryption import EncryptedReader, decrypt, encrypt_string, generate_key, get_expected_encrypted_length, get_expected_length_with_padding
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

BASE_URL = "https://cybersharing.net"


def get_username(token: str) -> bool:
    response = requests.get(f"{BASE_URL}/api/users/me", headers={"X-CliToken": token})
    response.raise_for_status()
    return response.json()["userName"]


def get_headers() -> dict:
    config = read_config()
    return {"X-CliToken": config["token"]} if config.get("token") else {}


def create_container(preupload_ids: List[str], password: str, encryption_salt: bytes | None, is_encrypted: bool, description: str | None, extra_long_url: bool, is_public: bool, save_to_history: bool, expiration_date: datetime.datetime) -> str:
    url = f"{BASE_URL}/api/upload/create-container"
    unlock_password = "".join([x.hex() for x in generate_key(password)]) if password else None
    payload = {
        "preuploads": preupload_ids,
        "description": description,
        "encryptionSalt": encryption_salt.hex() if encryption_salt else None,
        "expirationDate": expiration_date.isoformat() if expiration_date else None,
        "extraLongUrl": extra_long_url,
        "isEncrypted": is_encrypted,
        "isPublic": is_public,
        "password": unlock_password,
        "saveToHistory": save_to_history,
    }
    response = requests.post(url, json=payload, headers=get_headers())
    response.raise_for_status()
    response_json = response.json()
    return response_json["pathFragment"]


def get_container_details(fragment: str, password: str = None, salt: bytes = None, iterations: int = 10000, first_attempt: bool = True):
    url = f"{BASE_URL}/api/containers/{fragment}"
    unlock_password = generate_key(password, salt)[1].hex() if password and salt else None
    payload = {"password": unlock_password}

    response = requests.post(url, json=payload, headers=get_headers())

    if response.status_code == 400:
        error = response.json()
        if error["error"] == "Invalid password":
            salt = bytes.fromhex(error["salt"])
            iterations = error["iterations"]
            if first_attempt and password:
                return get_container_details(fragment, password, salt, iterations, first_attempt=False)
            elif not password:
                password = typer.prompt("Password", hide_input=True)
                return get_container_details(fragment, password, salt, iterations, first_attempt=False)
            else:
                typer.echo("Invalid password")
                raise typer.Abort()

    response.raise_for_status()
    return response.json(), password


def preupload_file(file: str, pad_to: int, encryption_key: bytes = None, encrypt: bool = False, padding: int = None) -> str:
    padding = (0 if not padding else padding) * 1024 * 1024
    file_size = os.path.getsize(file)
    file_name = os.path.basename(file)
    content_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"

    encrypted_file_name = encrypt_string(encryption_key, file_name) if encrypt else None
    encrypted_content_type = encrypt_string(encryption_key, content_type) if encrypt else None
    encrypted_file_size = encrypt_string(encryption_key, str(file_size)) if encrypt else None

    preupload_size = file_size if not encrypt else get_expected_encrypted_length(
        get_expected_length_with_padding(file_size, padding))

    def upload_callback(monitor: MultipartEncoderMonitor):
        progress = min(monitor.bytes_read / preupload_size, 1)
        typer.echo(f"Uploading {file_name.ljust(pad_to, ' ')} [{int(progress * 20) * '█':20s}] {progress:.0%}\r", nl=False)

    with open(file, "rb") as f:
        fields = {
            "size": str(preupload_size),
            "file": (file_name, f, content_type)
        } if not encrypt else {
            "size": str(preupload_size),
            "encryptedSize": encrypted_file_size,
            "file": (encrypted_file_name, EncryptedReader(f, file_size, encryption_key, padding), encrypted_content_type)
        }
        encoder = MultipartEncoder(fields)
        monitor = MultipartEncoderMonitor(encoder, upload_callback)
        headers = {"Content-Type": monitor.content_type}
        headers.update(get_headers())
        response = requests.post("https://cybersharing.net/api/upload/pre-upload", data=monitor, headers=headers)
        typer.echo("")
        response.raise_for_status()
        response_json = response.json()
        return response_json["id"]


def download_file(dest: str, container_id: str, upload_id: str, signature: str, filename: str, file_size: int, pad_to: int, encryption_key: bytes = None, total_files: int = 1, downloaded_files: int = 0):
    file_url = f"{BASE_URL}/api/download/file/{container_id}/{upload_id}/{signature}/{filename if not encryption_key else 'encrypted'}"
    dest_path = os.path.join(dest, filename)

    if os.path.commonprefix((os.path.realpath(dest_path), dest)) != dest:
        typer.echo(f"Invalid file name: {filename}")
        raise typer.Abort()

    response = requests.get(file_url, stream=True)
    response.raise_for_status()

    contentLength = int(response.headers.get("Content-Length"))
    file_downloaded_size = 0
    iv = None

    with open(dest_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=512 * 1024):
            abort = False
            if encryption_key:
                if not iv:
                    iv = chunk[:16]
                    chunk = chunk[16:]
                chunk = decrypt(encryption_key, iv, chunk)
                if file_downloaded_size == contentLength:
                    chunk = unpad(chunk, AES.block_size)
                file_downloaded_size += len(chunk)
                if file_downloaded_size > file_size:
                    excess = file_downloaded_size - file_size
                    chunk = chunk[:-excess]
                    abort = True
                iv = chunk[-16:]
            else:
                file_downloaded_size += len(chunk)

            f.write(chunk)

            progress = min(file_downloaded_size / file_size, 1)
            status_update_msg = f"Downloading {filename.ljust(pad_to)} [{'█' * int(progress * 20):20s}] {progress:.0%} ({total_files - downloaded_files - 1} left)"
            typer.echo(status_update_msg + "\r", nl=False)

            if abort:
                break

    typer.echo("")
