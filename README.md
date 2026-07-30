# CryptoCLI

`CryptoCLI` is a standalone CLI tool for performing symmetric encryption and decryption on files and directories.

**See the source code docstrings** for detailed parameter types and native multi-directory handling.

> Note: For maximum security, generated binary keys must be stored offline. Losing a key results in irreversible data loss.

## Quick start

No Python installation or external dependencies are required. Run the executable directly from the terminal or command prompt.

```bash
CryptoCLI.exe generatekey master.key --size 32
CryptoCLI.exe setsettings --algorithm AES256 --mode CBC --padding PKCS7
CryptoCLI.exe encryptfile data.txt master.key --fileDest data.enc --encrypt
```

For automated environments, generate custom settings files instead of relying on defaults. Settings are strictly validated before execution.

If `CTR` mode is selected, padding must be explicitly disabled:

```bash
CryptoCLI.exe setsettings -a AES256 -m CTR -p None
```

To reset to default settings, delete the `settings.json` file. The application will automatically apply the default `AES256/CBC/PKCS7` configuration during the next run.

## Configuration Parameters

Encryption parameters are managed via a JSON state file. 

| Parameter | Supported Values | Definition |
|---|---|---|
| **Algorithms** | `AES`, `AES128`, `AES256`, `SM4` | Block cipher implementations. |
| **Modes** | `CBC`, `CTR` | Operating modes (Block Chaining / Stream Counter). |
| **Padding** | `PKCS7`, `ANSIX923`, `None` | Block alignment mechanisms. `None` is required for `CTR`. |

## Directory Operations

`encryptdir` recursively processes all files within a directory and mirrors the internal folder tree in the destination path.

```bash
# Encrypt directory
CryptoCLI.exe encryptdir ./source_folder master.key --dirDest ./encrypted_folder -e

# Decrypt directory
CryptoCLI.exe encryptdir ./encrypted_folder master.key --dirDest ./decrypted_folder -d
```

## Python SDK

The core `FileEncryption` class can be integrated directly into other Python applications. It supports dynamic IV generation and handles memory buffering automatically.

```python
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives import padding
from main import FileEncryption, readKey

# 1. Load key
key = readKey("master.key")

# 2. Initialize and configure cryptography module
crypto = FileEncryption()
crypto.load_setting(key, algorithms.AES, modes.CBC, padding.PKCS7)

# 3. Execute stream operation
crypto.readSaveEncryptDecrypt(
    filePath="data.txt",
    destPath="data.enc",
    encrypt=True
)
```
