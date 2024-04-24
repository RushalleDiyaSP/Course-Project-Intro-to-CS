import socket

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# Load server's private key
with open("server_private.pem", "r") as file:
    server_private_key = RSA.import_key(file.read())

# Load bank's public key
with open("bank_public.pem", "r") as file:
    bank_public_key = RSA.import_key(file.read())

def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

def decrypt_message(ciphertext):
    cipher = PKCS1_OAEP.new(server_private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

def load_item_data(file_path):
    with open(file_path, "r") as file:
        item_data = file.read()
    return item_data

def main():
    item_data = load_item_data("items.txt")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(('localhost', 12345))
    server_socket.sendall(item_data.encode())
    
    data = server_socket.recv(1024).decode()
    print("Received item data from bank:", data)
    
    server_socket.close()

if __name__ == "__main__":
    main()
