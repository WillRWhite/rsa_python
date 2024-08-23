from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def load_private_key(filename, password=None):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key

def decrypt_message(encrypted_message, private_key):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def main():
    # Load the encrypted message from a file
    with open("encrypted_message.bin", "rb") as file:
        encrypted_message = file.read()

    # Load the private key
    private_key = load_private_key("private_key.pem", password=b"aaaaaa")

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, private_key)

    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()