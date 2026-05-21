import subprocess
import json
import requests
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


def get_azure_cli_access_token(resource: str = 'https://api.fabric.microsoft.com') -> str:
    cmd = f'az account get-access-token --resource {resource} --output json'
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,  # <-- This enables cmd.exe resolution
        text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"Azure CLI error: {result.stderr}")
    token_data = json.loads(result.stdout)
    return token_data['accessToken']


def get_public_key_from_gateway(gateway_id: str, access_token: str) -> (str, str):
    url = f"https://api.fabric.microsoft.com/v1/gateways/{gateway_id}"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    return data['publicKey']['exponent'], data['publicKey']['modulus']


# ==== Existing encryption logic unchanged ====

def map_generated_key_length(key: bytes) -> int:
    if len(key) == 32:
        return 0
    elif len(key) == 64:
        return 1
    else:
        raise ValueError(f"Unsupported key length: {len(key)}")


def concat_arrays(*arrays: bytes) -> bytes:
    return b''.join(arrays)


def get_signed_payload(ciphertext: bytes, iv: bytes, sign_key: bytes) -> str:
    algorithms = bytes([0, 0])
    to_sign = concat_arrays(algorithms, iv, ciphertext)
    hmac = HMAC.new(sign_key, digestmod=SHA256)
    hmac.update(to_sign)
    signature = hmac.digest()
    full_payload = concat_arrays(algorithms, signature, iv, ciphertext)
    return b64encode(full_payload).decode('utf-8')


def encrypt_keys(modulus_b64: str, exponent_b64: str, symmetric_key: bytes, sign_key: bytes) -> str:
    modulus_bytes = b64decode(modulus_b64 + '==')
    exponent_bytes = b64decode(exponent_b64 + '==')
    modulus_int = int.from_bytes(modulus_bytes, byteorder='big')
    exponent_int = int.from_bytes(exponent_bytes, byteorder='big')
    rsa_key = RSA.construct((modulus_int, exponent_int))
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)

    lengths = bytes([map_generated_key_length(symmetric_key), map_generated_key_length(sign_key)])
    combined_keys = concat_arrays(lengths, symmetric_key, sign_key)
    encrypted_keys = cipher_rsa.encrypt(combined_keys)
    return b64encode(encrypted_keys).decode('utf-8')


def encrypt_credentials_full(credentials: str, gateway_id: str) -> str:
    access_token = get_azure_cli_access_token()
    exponent_b64, modulus_b64 = get_public_key_from_gateway(gateway_id, access_token)

    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    sign_key = bytearray(get_random_bytes(64))

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padding_len = 16 - (len(credentials.encode()) % 16)
    padded_credentials = credentials.encode() + bytes([padding_len] * padding_len)
    ciphertext = cipher_aes.encrypt(padded_credentials)

    signed_payload = get_signed_payload(ciphertext, iv, sign_key)
    encrypted_keys = encrypt_keys(modulus_b64, exponent_b64, aes_key, sign_key)

    for i in range(len(sign_key)):
        sign_key[i] = 0

    return encrypted_keys + signed_payload


def build_key_pair_credentials(username: str, privatekey: str, passphrase: str) -> str:
    payload = {
        "credentialData": [
            {"name": "username", "value": username},
            {"name": "privatekey", "value": privatekey},
            {"name": "passphrase", "value": passphrase},
        ]
    }
    return json.dumps(payload, separators=(',', ':'))


# === Sample Run ===
if __name__ == "__main__":
    gateway_id = ""
    username = ""
    privatekey = ""
    passphrase = ""
    output_path = ""

    credentials = build_key_pair_credentials(username, privatekey, passphrase)
    print("Starting encryption using Azure CLI authentication...")
    encrypted = encrypt_credentials_full(credentials, gateway_id)

    with open(output_path, "w") as f:
        f.write(encrypted)
    print(f"Encrypted payload written to {output_path}")
