import socket
import traceback
from math import e

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

# Load bank's private key
with open("bank_private.pem", "r") as file:
    bank_private_key = RSA.import_key(file.read())

# Load server's public key
with open("server_public.pem", "r") as file:
    server_public_key = RSA.import_key(file.read())

# Load creditinfo data from file
def load_creditinfo():
    creditinfo = {}
    with open("creditinfo.txt", "r") as file:
        for line in file:
            name, hashed_card, available_credits = line.strip().split()
            creditinfo[name] = (hashed_card, int(available_credits))
    return creditinfo

# Function to update available credits in creditinfo file
def update_creditinfo(name, new_available_credits):
    creditinfo = load_creditinfo()
    creditinfo[name] = (creditinfo[name][0], new_available_credits)
    with open("creditinfo.txt", "w") as file:
        for name, (hashed_card, available_credits) in creditinfo.items():
            file.write(f"{name} {hashed_card} {available_credits}\n")

# Sign data using bank's private key
def sign(data):
    h = SHA256.new(data)
    signer = PKCS1_v1_5.new(bank_private_key)
    signature = signer.sign(h)
    return signature

# Verify signature using server's public key
def verify_signature(data, signature, public_key):
    h = SHA256.new(data)
    verifier = PKCS1_v1_5.new(public_key)
    return verifier.verify(h, signature)

# Validate transaction (dummy implementation)
def validate_transaction(customer_data):
    # Implement customer validation logic here
    return True  # For simplicity, always return True

# Handle transaction
def handle_transaction(data):
    data_parts = data.split("||")
    encrypted_message = data_parts[0]
    signature = data_parts[1]
    
    if verify_signature(encrypted_message.encode(), signature.encode(), server_public_key):
        # Decrypt encrypted_message, validate transaction, update credits, and return response
        if validate_transaction(encrypted_message):
            return "1"  # Success
        else:
            return "0"  # Unauthorized
    else:
        return "0"  # Unauthorized

# Main function
def main():
    try:
        # Load creditinfo data from file
        load_creditinfo()
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 12345))
        server_socket.listen(1)
        print("Bank is listening...")
        
        while True:
            conn, addr = server_socket.accept()
            with conn:
                print('Connected by', addr)
                data = conn.recv(1024).decode()
                response = handle_transaction(data)
                conn.sendall(response.encode())
                
    except Exception as e:
        print("Error occurred in bank:", e)
        traceback.print_exc()  # Print traceback for detailed error information

if __name__ == "__main__":
    main()
