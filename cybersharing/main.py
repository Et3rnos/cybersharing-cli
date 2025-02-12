import binascii
import datetime
import requests
import typer
import re
import os
from typing import List
from base64 import b64encode
import json

from cybersharing.api import create_container, download_file, get_container_details, get_username, preupload_file
from cybersharing.config import read_config, write_config
from cybersharing.encryption import decrypt_string, generate_key

main = typer.Typer()


def validate_auth():
    config = read_config()
    username = config.get("username")
    if username:
        try:
            new_username = get_username(read_config()["token"])
        except requests.exceptions.HTTPError:
            typer.echo("Authentication failed. Please logout or login again.")
            raise typer.Abort()

        if new_username != username:
            write_config({
                "token": config["token"],
                "username": new_username
            })

        typer.echo(f"Logged in as {new_username}")


@main.command()
def logout():
    """
    Logout from the API.
    """

    write_config({})
    typer.echo("Logged out successfully")


@main.command()
def login(token: str):
    """
    Login to the API.
    """

    try:
        username = get_username(token)
    except requests.exceptions.HTTPError as e:
        typer.echo("Invalid token")
        raise typer.Abort()

    config = {
        "token": token,
        "username": username
    }

    write_config(config)
    typer.echo("Logged in successfully")


@main.command()
def upload(files: List[str],
           password: str = typer.Option(None, help="Password for your files"),
           encrypt: bool = typer.Option(False, help="Whether to encrypt the files"),
           padding: int = typer.Option(None, help="Padding in MiB for encryption"),
           description: str = typer.Option(None, help="Description of the upload"),
           extra_long_url: bool = typer.Option(False, help="Generate an extra long URL"),
           public: bool = typer.Option(False, help="Add the upload to your public profile"),
           save_to_history: bool = typer.Option(False, help="Save the upload to the IP history"),
           permanent: bool = typer.Option(False, help="Disable expiration date"),
           expiration_date: datetime.datetime = typer.Option(datetime.datetime.now(
           ) + datetime.timedelta(days=7), help="Expiration date, defaults to 7 days from now"),
           expiration_days: int = typer.Option(None, help="Relative expiration time in days"),
           expiration_hours: int = typer.Option(None, help="Relative expiration time in hours"),
           expiration_minutes: int = typer.Option(None, help="Relative expiration time in minutes"),
           generate_password: bool = typer.Option(False, help="Generate a random secure password"),
           auth_check: bool = typer.Option(True, help="Check if the user is authenticated before uploading")
           ):
    """
    Upload files.
    """

    if auth_check:
        validate_auth()

    if generate_password:
        password = b64encode(os.urandom(32)).decode().rstrip("=")
        typer.echo(f"Generated password: {password}")

    if encrypt and not password:
        password = typer.prompt("Password", hide_input=True)
        if not password:
            typer.echo("Password is required for encryption")
            raise typer.Abort()

    encryption_salt, encryption_key = generate_key(password) if encrypt else (None, None)

    for file in files:
        if not os.path.exists(file):
            typer.echo(f"File {file} not found")
            raise typer.Abort()

    max_filename_length = max([len(os.path.basename(file)) for file in files])

    if expiration_days or expiration_hours or expiration_minutes:
        expiration_date = datetime.datetime.now()
        if expiration_days:
            expiration_date += datetime.timedelta(days=expiration_days)
        if expiration_hours:
            expiration_date += datetime.timedelta(hours=expiration_hours)
        if expiration_minutes:
            expiration_date += datetime.timedelta(minutes=expiration_minutes)

    authenticated = read_config().get("username") is not None
    if expiration_date < datetime.datetime.now() + datetime.timedelta(minutes=5):
        typer.echo("Minimum expiration time is 5 minutes")
        raise typer.Abort()
    elif not authenticated and (expiration_date > datetime.datetime.now() + datetime.timedelta(days=7) or permanent):
        typer.echo("Maximum expiration time for anonymous users is 7 days. Please login to remove this limit.")
        raise typer.Abort()

    if permanent:
        expiration_date = None

    preupload_ids = []
    for file in files:
        preupload_id = preupload_file(file, max_filename_length, encryption_key, encrypt, padding)
        preupload_ids.append(preupload_id)

    fragment = create_container(preupload_ids, password, encryption_salt, encrypt, description, extra_long_url, public, save_to_history, expiration_date)
    typer.echo(f"Access your files at https://cybersharing.net/s/{fragment}")


@main.command()
def download(url: str,
             dest: str = typer.Option(".", help="Destination directory for the downloaded files"),
             password: str = typer.Option(None, help="Password for your files"),
             auth_check: bool = typer.Option(True, help="Check if the user is authenticated before downloading")
             ):
    """
    Download a file from a URL.
    """

    if auth_check:
        validate_auth()

    if not re.match(r"https://cybersharing.net/s/[0-9a-f]+", url):
        typer.echo("Invalid URL")
        raise typer.Abort()

    fragment = url.split("/")[-1]
    details, password = get_container_details(fragment, password)

    uploads = details["uploads"]
    total_files = len(uploads)
    dest = os.path.abspath(dest)
    downloaded_files = 0

    encryption_key = generate_key(password, bytes.fromhex(details["encryptionSalt"]))[1] if details["isEncrypted"] else None

    if encryption_key:
        for upload in uploads:
            upload["fileName"] = decrypt_string(encryption_key, upload["fileName"])
            upload["contentType"] = decrypt_string(encryption_key, upload["contentType"])
            upload["fileSize"] = int(decrypt_string(encryption_key, upload["encryptedFileSize"]))

    max_filename_length = max([len(upload["fileName"]) for upload in uploads])
    total_size = sum([upload["fileSize"] for upload in uploads])

    for upload in uploads:
        download_file(dest, details["id"], upload["id"], details["signature"], upload["fileName"],
                      upload["fileSize"], max_filename_length, encryption_key, total_files, downloaded_files)
        downloaded_files += 1

    typer.echo(f"Downloaded {total_files} files ({total_size} bytes) to {dest}")


if __name__ == "__main__":
    main()
