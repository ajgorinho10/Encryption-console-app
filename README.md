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
