from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64

server_socket = None
server_status = 0
buffer_size = 1024
all_clients = {}
counter = 0
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()
client_public_keys = {}  # To store clients' public keys


def encrypt_message(message, recipient_public_key):
    # Compute the hash
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(message.encode())
    message_hash = digest.finalize()

    # Append the hash to the message
    full_message = message.encode() + b"||" + message_hash

    # Encrypt using recipient's public key
    encrypted_message = recipient_public_key.encrypt(
        full_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return encrypted_message


def decrypt_message(encrypted_message):
    # Decrypt using own private key
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # Split the message and the hash
    message, received_hash = decrypted_message.rsplit(b"||", 1)

    # Recalculate the hash of the message
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(message)
    calculated_hash = digest.finalize()

    # Verify integrity
    if calculated_hash != received_hash:
        raise ValueError("Message integrity compromised!")

    return message.decode()


x = "i am mahad"
print(x)
y = encrypt_message(x, public_key)
print(f"{y}".encode())
print(f"{y}".encode().decode())

z = decrypt_message(f"{y}".encode().decode())
print(z)
