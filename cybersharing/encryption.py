import io
import os
import hashlib
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    salt = os.urandom(16) if not salt else salt
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 10000, dklen=32)
    return (salt, derived_key)


def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(data)


def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(data)


def encrypt_string(key: bytes, data: str) -> str:
    iv = os.urandom(16)
    data = data.ljust(1024, "\0")
    return iv.hex() + encrypt(key, iv, pad(data.encode(), AES.block_size)).hex()


def decrypt_string(key: bytes, data: str) -> str:
    iv = bytes.fromhex(data[:32])
    data = bytes.fromhex(data[32:])
    return unpad(decrypt(key, iv, data), AES.block_size).decode().rstrip("\0")


def get_expected_encrypted_length(plaintext_length: int) -> int:
    return 16 + plaintext_length // 16 * 16 + 16

def get_expected_length_with_padding(plaintext_length: int, padding: int) -> int:
    return plaintext_length + padding - plaintext_length % padding if padding else plaintext_length


class EncryptedReader(io.IOBase):
    def __init__(self, file: io.BufferedReader, size: int, key: bytes, padding: int):
        self.key = key
        self.position = 0
        self.iv = None

        # source file
        self.file = file
        self.file_length = size

        self.file_length_with_padding = get_expected_length_with_padding(size, padding)
        self.padding_left = self.file_length_with_padding - size

        self.encrypted_length = get_expected_encrypted_length(self.file_length_with_padding)

        self.remaining_data = b""

    def read(self, size: int = -1):
        # if the last block wasn't fully read, add it to the beginning of the next read
        chunk = self.remaining_data
        self.remaining_data = b""
        size -= len(chunk)

        # size here is always larger than 16
        if not self.iv:
            self.iv = os.urandom(16)
            size -= 16
            chunk += self.iv

        # how many bytes of the last block should be sent
        remainder = size % 16

        block_position = self.position + size
        should_pad = block_position >= self.file_length_with_padding

        # the data will be processed based on this size
        ceiling_size = size - remainder + 16
        plaintext = self.file.read(ceiling_size)

        # pad with dummy data if necessary
        padding_amount = min(ceiling_size - len(plaintext), self.padding_left)
        self.padding_left -= padding_amount
        plaintext += b"\0" * padding_amount

        self.position += size

        if plaintext:
            chunk += encrypt(self.key, self.iv, pad(plaintext, AES.block_size) if should_pad else plaintext)

        self.iv = chunk[-32:-16] if remainder else chunk[-16:]
        self.remaining_data = chunk[-16+remainder:] if remainder else b""
        chunk = chunk[:-16+remainder] if remainder else chunk

        return chunk

    def seek(self, offset: int, whence: int = 0):
        assert offset == self.position, "seek only supports current position"
        self.position = offset
        return self.position

    def tell(self):
        return self.position

    def __len__(self):
        return self.encrypted_length
