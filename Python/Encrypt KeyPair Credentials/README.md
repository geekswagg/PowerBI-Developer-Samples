# Encrypt KeyPair Credentials

Sample script for programmatically encrypting **KeyPair** credentials against a
Fabric / Power BI on-premises gateway.

---

## Credential fields

| Field        | Required | Description                                              |
|--------------|----------|----------------------------------------------------------|
| `username`   | Yes      | Username associated with the private key                 |
| `privatekey` | Yes      | Private key in PKCS #8 PEM format                        |
| `passphrase` | No       | Passphrase protecting the private key. Omit if not set.  |

---

## Prerequisites

- Python 3.8 or later
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) — run `az login` once before executing the script

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Run

1. Open `encrypt.py` and fill in the placeholder values in the `if __name__ == "__main__":` block:

   ```python
   gateway_id  = "<your-gateway-id>"
   username    = "<username>"
   privatekey  = "<private key>"
   passphrase  = "<passphrase>"   # leave empty string if the key has no passphrase
   output_path = "encrypted_payload.txt"
   ```

2. Execute:

   ```bash
   python encrypt.py
   ```
