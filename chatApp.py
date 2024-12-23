import base64
import socket
import threading
from base64 import b64encode
from tkinter import Tk, Frame, Text, Label, Entry, Button, Listbox, StringVar, DISABLED, NORMAL, E, W, N, S
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from ip import get_working_private_ip
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class ChatClient(Frame):

    def __init__(self, root, ipAdd):
        super().__init__(root)
        self.root = root
        self.ipAdd = ipAdd
        self.init_ui()
        self.server_socket = None
        self.server_status = 0
        self.buffer_size = 2048
        self.all_clients = {}
        self.all_clients_add = {}
        self.counter = 0
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()
        self.client_public_keys = {}  # To store clients' public keys

    def init_ui(self):
        self.root.title("Simple P2P Chat Client")
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        frame_width, frame_height = 800, 600
        pos_x = (screen_width - frame_width) // 2
        pos_y = (screen_height - frame_height) // 2
        self.root.geometry(f"{frame_width}x{frame_height}+{pos_x}+{pos_y}")
        self.root.resizable(False, False)

        padx, pady = 10, 10
        parent_frame = Frame(self.root)
        parent_frame.grid(padx=padx, pady=pady, sticky=E + W + N + S)

        # IP and Client setup frame
        ip_group = Frame(parent_frame)
        Label(ip_group, text="Set: ").grid(row=0, column=0)
        self.name_var = StringVar(value="SDH")
        Entry(ip_group, width=10, textvariable=self.name_var).grid(row=0, column=1)

        self.server_ip_var = StringVar(value=f"{self.ipAdd}")
        Entry(ip_group, width=15, textvariable=self.server_ip_var).grid(row=0, column=2)

        self.server_port_var = StringVar(value="8091")
        Entry(ip_group, width=5, textvariable=self.server_port_var).grid(row=0, column=3)

        Button(ip_group, text="Set", width=10, command=self.handle_set_server).grid(row=0, column=4, padx=5)

        Label(ip_group, text="Add friend: ").grid(row=0, column=5)
        self.client_ip_var = StringVar(value="127.0.0.1")
        Entry(ip_group, width=15, textvariable=self.client_ip_var).grid(row=0, column=6)

        self.client_port_var = StringVar(value="8091")
        Entry(ip_group, width=5, textvariable=self.client_port_var).grid(row=0, column=7)

        Button(ip_group, text="Add", width=10, command=self.handle_add_client).grid(row=0, column=8, padx=5)
        ip_group.grid(row=0, column=0)

        # Chat display
        read_chat_group = Frame(parent_frame)
        self.received_chats = Text(read_chat_group, bg="white", width=60, height=30, state=DISABLED)
        self.received_chats.grid(row=0, column=0, sticky=W + N + S, padx=(0, 10))

        self.friends = Listbox(read_chat_group, bg="white", width=30, height=30)
        self.friends.grid(row=0, column=1, sticky=E + N + S)
        read_chat_group.grid(row=1, column=0)

        # Chat input
        write_chat_group = Frame(parent_frame)
        self.chat_var = StringVar()
        Entry(write_chat_group, width=80, textvariable=self.chat_var).grid(row=0, column=0, sticky=W)
        Button(write_chat_group, text="Send", width=10, command=self.handle_send_chat).grid(row=0, column=1, padx=5)
        write_chat_group.grid(row=2, column=0, pady=10)

        self.status_label = Label(parent_frame)
        self.status_label.grid(row=3, column=0)

    def encrypt_message(self, message, recipient_public_key):
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

    def decrypt_message(self, encrypted_message):
        # Decrypt using own private key
        decrypted_message = self.private_key.decrypt(
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

    def handle_set_server(self):
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
            self.server_status = 0

        server_address = (self.server_ip_var.get().strip(), int(self.server_port_var.get().strip()))

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(server_address)
            self.server_socket.listen(5)
            self.set_status(f"Server listening on {server_address[0]}:{server_address[1]}")

            threading.Thread(target=self.listen_clients, daemon=True).start()
            self.server_status = 1
            self.name = self.name_var.get().strip() or f"{server_address[0]}:{server_address[1]}"
        except Exception as e:
            self.set_status(f"Error setting up server: {e}")

    def listen_clients(self):
        while True:
            try:
                client_socket, client_address = self.server_socket.accept()

                self.set_status(f"Client connected from {client_address[0]}:{client_address[1]}")
                data = client_socket.recv(self.buffer_size)
                if not data:
                    break
                message = data.decode()
                self.client_public_keys[f"{client_address[0]}:{client_address[1]}"] = message
                client_socket.send(self.public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo
                ).decode().encode())

                self.add_client(client_socket, client_address)

                threading.Thread(target=self.handle_client_messages, args=(client_socket, client_address),
                                 daemon=True).start()
            except Exception as e:
                self.set_status(f"Error listening to clients: {e}")

    def handle_add_client(self):
        if self.server_status == 0:
            self.set_status("Set server address first")
            return

        client_address = (self.client_ip_var.get().strip(), int(self.client_port_var.get().strip()))

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(client_address)
            self.set_status(f"Connected to client on {client_address[0]}:{client_address[1]}")
            client_socket.send(self.public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode().encode())

            self.add_client(client_socket, client_address)
            threading.Thread(target=self.handle_client_messages, args=(client_socket, client_address),
                             daemon=True).start()
        except Exception as e:
            self.set_status(f"Error connecting to client: {e}")

    def handle_client_messages(self, client_socket, client_address):

        while True:
            try:
                data = client_socket.recv(self.buffer_size)
                if not data:
                    break
                message = data.decode()
                if message.startswith("-----BEGIN PUBLIC KEY-----") and message.endswith(
                        "-----END PUBLIC KEY-----\n"):
                    self.client_public_keys[f"{client_address[0]}:{client_address[1]}"] = message
                else:
                    self.add_chat(f"{client_address[0]}:{client_address[1]}", self.decrypt_message(eval(message)))
            except Exception as e:
                self.set_status(f"Error receiving data: {e}")
                break

        # Remove client and close connection
        self.remove_client(client_socket, client_address)
        client_socket.close()
        self.set_status(f"Client disconnected from {client_address[0]}:{client_address[1]}")

    def handle_send_chat(self):
        if self.server_status == 0:
            self.set_status("Set server address first")
            return

        msg = self.chat_var.get().strip()
        if not msg:
            return

        self.add_chat("me", msg)
        self.chat_var.set("")
        for client_socket in list(self.all_clients.keys()):
            try:
                add = self.all_clients_add[client_socket]
                pem_string = self.client_public_keys[f"{add[0]}:{add[1]}"]
                public_key = load_pem_public_key(pem_string.encode())
                encrypted_message = self.encrypt_message(msg, public_key)
                client_socket.send(str(encrypted_message).encode())
            except Exception as e:
                self.set_status(f"Error sending message: {e}")

    def add_chat(self, sender, message):
        self.received_chats.config(state=NORMAL)
        self.received_chats.insert("end", f"{sender}: {message}\n")
        self.received_chats.config(state=DISABLED)

    def add_client(self, client_socket, client_address):
        self.all_clients[client_socket] = self.counter
        self.all_clients_add[client_socket] = client_address

        self.counter += 1
        self.friends.insert(self.counter, f"{client_address[0]}:{client_address[1]}")

    def remove_client(self, client_socket, client_address):
        if client_socket in self.all_clients:
            self.friends.delete(self.all_clients[client_socket])
            del self.all_clients[client_socket]
            del self.all_clients_add[client_socket]

    def set_status(self, message):
        self.status_label.config(text=message)
        print(message)


if __name__ == "__main__":
    root = Tk()
    ip = get_working_private_ip()
    app = ChatClient(root, ip)
    root.mainloop()
