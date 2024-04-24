import socket

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# Load server's public key
with open("server_public.pem", "r") as file:
    server_public_key = RSA.import_key(file.read())

def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

def hash_credit_card_number(credit_card_number):
    hashed_card = SHA256.new(credit_card_number.encode()).hexdigest()
    return hashed_card

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(('localhost', 12345))
    
    data = server_socket.recv(1024).decode()
    print("Received item data from server:", data)
    
    item_number = input("Enter the item number you wish to purchase: ")
    name = input("Enter your name: ")
    credit_card_number = input("Enter your credit card number: ")
    
    # Hash credit card number
    hashed_card = hash_credit_card_number(credit_card_number)
    
    # Encrypt customer data
    encrypted_customer_data = encrypt_message(item_number + "||" + name + "||" + hashed_card, server_public_key)
    
    # Send encrypted data to server
    server_socket.sendall(encrypted_customer_data)
    
    response = server_socket.recv(1024).decode()
    if response == "1":
        print("Your order is confirmed.")
    else:
        print("Credit card transaction is unauthorized.")
    
    server_socket.close()

if __name__ == "__main__":
    main()
