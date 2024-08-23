import base64
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def load_rfc4253_public_key(filename):
    with open(filename, "r") as key_file:
        key_data = key_file.read().strip()
    
    # The key is usually in the format: ssh-rsa <base64-encoded key>
    if key_data.startswith("ssh-rsa "):
        key_data = key_data.split()[1]
    
    key_bytes = base64.b64decode(key_data)

    # Parse the key according to the SSH RFC 4253 format
    key_type_len = struct.unpack('>I', key_bytes[:4])[0]
    key_type = key_bytes[4:4 + key_type_len].decode()

    if key_type != "ssh-rsa":
        raise ValueError("Invalid key type. Expected 'ssh-rsa'.")

    exponent_len = struct.unpack('>I', key_bytes[4 + key_type_len:8 + key_type_len])[0]
    exponent = key_bytes[8 + key_type_len:8 + key_type_len + exponent_len]

    modulus_len = struct.unpack('>I', key_bytes[8 + key_type_len + exponent_len:12 + key_type_len + exponent_len])[0]
    modulus = key_bytes[12 + key_type_len + exponent_len:12 + key_type_len + exponent_len + modulus_len]

    public_numbers = rsa.RSAPublicNumbers(
        e=int.from_bytes(exponent, byteorder='big'),
        n=int.from_bytes(modulus, byteorder='big')
    )
    
    return public_numbers.public_key()

def convert_to_pem(public_key, output_filename):
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(output_filename, "wb") as pem_file:
        pem_file.write(pem_data)
    print(f"PEM public key saved to {output_filename}")

def main():
    # Load the RFC 4253 public key
    public_key = load_rfc4253_public_key("mykey.pub")

    # Convert and save the PEM public key
    convert_to_pem(public_key, "mykey_pub.pem")

if __name__ == "__main__":
    main()