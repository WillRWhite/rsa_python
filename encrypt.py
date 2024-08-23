# pip install cryptography
# Key generation (Linux)
# openssl genpkey -algorithm RSA -out private_key.pem -aes256
# openssl rsa -pubout -in private_key.pem -out public_key.pem

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_message(message, public_key):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def main():
    # Read the message from a file
    with open("message.txt", "r") as file:
        message = file.read()

    # Load the public key
    public_key = load_public_key("public_key.pem")

    # Encrypt the message
    encrypted_message = encrypt_message(message, public_key)

    # Save the encrypted message to a file
    with open("encrypted_message.bin", "wb") as file:
        file.write(encrypted_message)

    print("Message encrypted and saved to encrypted_message.bin")

if __name__ == "__main__":
    main()