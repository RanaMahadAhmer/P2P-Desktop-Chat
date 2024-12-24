from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def encrypt_message(message, recipient_public_key):
    # Convert message to bytes
    message_bytes = message.encode()

    # Calculate maximum block size (RSA key size in bytes - padding overhead)
    block_size = 190  # 2048 bit key = 256 bytes - padding overhead

    # Split message into blocks
    blocks = [message_bytes[i:i + block_size] for i in range(0, len(message_bytes), block_size)]

    # Encrypt each block
    encrypted_blocks = []
    for block in blocks:
        # Add length prefix to distinguish final block
        block_with_length = len(block).to_bytes(2, 'big') + block

        # Encrypt block with RSA
        encrypted_block = recipient_public_key.encrypt(
            block_with_length,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        encrypted_blocks.append(encrypted_block)

    # Combine all blocks into a single bytes object
    return b''.join(encrypted_blocks)


public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4bDp6TZkWR1Ge/nPO7to
PtHsGW113cZ/STYgiQsnHufzANAkWJMNF64S7ZXNR0XJf+NAiDoKzpfYr+HTpKv1
EJawwG/O+76pIzM0mGIh2JauXpIXf/lTEArZozPdp1LGlVW7F5J54opsoMwe1oQR
NkznGHQ4ZWtaExZT1ZTdUUjm/kEf6Ic+zZsphMFx+HOdd32o7kFwNOB+9PgX1Kmy
MhV59HEQCBFThDn7ABmNM5lEEMi6S4Jf1xRE7+qyGJDfNVMg70lud4ngTgO2Svic
ghRMUAR+Z6tkw3nhPBxXgJ7zbzrwB/lN1apE6+ToX/9hDHzHLQ2qLH/CLvZkmjQk
RQIDAQAB
-----END PUBLIC KEY-----

"""

pub = load_pem_public_key(public_key_pem.encode(), backend=default_backend())
x = encrypt_message("You have been hacked!", pub)

import socket


# Function to send encrypted message to the specified IP and port
def send_packet_to_server(ip, port, data):
    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            # Connect to the server
            client_socket.connect((ip, port))
            # Send the encrypted data
            client_socket.sendall(data)
            print(f"Packet sent to {ip}:{port}")
        except Exception as e:
            print(f"Failed to send packet: {e}")


# IP address and port
server_ip = "10.7.152.182"
server_port = 8091

# Encrypted message to send
packet_data = str(x).encode()

# Send the packet
send_packet_to_server(server_ip, server_port, packet_data)
