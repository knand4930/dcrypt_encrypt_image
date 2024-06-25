
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


def encrypt_image(input_image_path, output_encrypted_path, password):
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    iv = os.urandom(16)

    with open(input_image_path, 'rb') as f:
        image_data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_image_data = padder.update(image_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_image_data = encryptor.update(padded_image_data) + encryptor.finalize()

    with open(output_encrypted_path, 'wb') as f:
        f.write(salt + iv + encrypted_image_data)


def decrypt_image(encrypted_image_path, output_decrypted_path, password):
    with open(encrypted_image_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_image_data = f.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_image_data = decryptor.update(encrypted_image_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    image_data = unpadder.update(padded_image_data) + unpadder.finalize()

    with open(output_decrypted_path, 'wb') as f:
        f.write(image_data)


password = "Kishore#@123"
encrypt_image('logo-main.png', 'encrypted_image.bin', password)
decrypt_image('encrypted_image.bin', 'decrypted_image.jpg', password)
