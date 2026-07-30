import os
import io
import time
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives import padding

from typing import Annotated
import typer

app = typer.Typer()

# ----------------------------------
#                                  |
# class to encrypt / decrypt files |
#                                  |
# ----------------------------------
class FileEncryption:
    def __init__(self):
        self.key = None
        
        self.algorithm = None
        self.mode = None
        self.padding = None

        
    def load_setting(
        self,
        key:bytes,
        algorithm:algorithms, 
        mode:modes,
        padd:padding
    )->None:
        self.key = key
        self.algorithm = algorithm
        self.mode = mode
        self.padding = padd
        

    def readSaveEncryptDecrypt(
        self,
        filePath: str,
        destPath: str = None,
        encrypt: bool = True
    ) -> None:
        '''
        Szyfrowanie/odszyfrowanie pliku
        
            Args:
                -filePath: ścieżka do pliku źródłowego
                -destPath: ścieżka do pliku docelowego
                -encrypt:  szyfrowanie lub odsyfrowywanie
        '''
        
        bufferSize = 131072     # Rozmiar buffora
        bufferReadSize = 65536  # Rozmiar danych do czytania

        if destPath is None:
            destPath = "tmp.txt"
            

        startTime = time.time()
        
        try:
            with open(filePath, mode="rb", buffering=0) as fileToEncrypt, \
                open(destPath, mode='wb', buffering=0) as fileToSave:
                readBuffer = io.BufferedReader(fileToEncrypt, bufferSize)   #   Buffor odczytu
                saveBuffer = io.BufferedWriter(fileToSave,    bufferSize)   #   Buffor zapisu
                
                algo_instance = self.algorithm(self.key)
                block_size_bits = algo_instance.block_size
                iv_size_bytes = block_size_bits // 8
                    
                # Odczytywanie i generownie wektora IV (16 bajtów) na początku pliku
                iv = None
                if encrypt:
                    iv = os.urandom(iv_size_bytes)
                    saveBuffer.write(iv)
                else:
                    iv = readBuffer.read(iv_size_bytes)
                    
                # Inicjalizacja kryptografii
                cipher = Cipher(algo_instance, self.mode(iv))
                ed = cipher.encryptor() if encrypt else cipher.decryptor()
                
                # Weryfikacja, czy tryb wymaga paddingu
                requires_padding = self.mode != modes.CTR

                if requires_padding:
                    padder_unpadder = self.padding(block_size_bits).padder() if encrypt else self.padding(block_size_bits).unpadder()
                
                # Czytamy pierwesze 65536 bajtów (bufferReadSize) do 'msg'
                msg = readBuffer.read(bufferReadSize)
                while msg:
                    if encrypt:
                        if requires_padding:
                            padded_data = padder_unpadder.update(msg)
                            saveBuffer.write(ed.update(padded_data))
                        else:
                            saveBuffer.write(ed.update(msg))
                    else:
                        decrypted_data = ed.update(msg)
                        if requires_padding:
                            saveBuffer.write(padder_unpadder.update(decrypted_data))
                        else:
                            saveBuffer.write(decrypted_data)
                        
                    msg = readBuffer.read(bufferReadSize) # czytamy nowe dane -> 'msg'
                
                if encrypt:
                    if requires_padding:
                        padded_data = padder_unpadder.finalize()
                        saveBuffer.write(ed.update(padded_data) + ed.finalize())
                    else:
                        saveBuffer.write(ed.finalize())
                else:
                    decrypted_data = ed.finalize()
                    if requires_padding:
                        saveBuffer.write(padder_unpadder.update(decrypted_data) + padder_unpadder.finalize())
                    else:
                        saveBuffer.write(decrypted_data)
                
                # Zapisujemy buffor(saveBuffer) do pliku przed zamknięciem deskryptorów
                saveBuffer.flush()

            stopTime = time.time()
            print(f'Operacja zakończona w {(stopTime-startTime):.05f} s')
            
            # podmieniamy pliki
            if destPath == "tmp.txt":
                os.replace(os.path.abspath(destPath), filePath)
        
        except Exception as e:
            print(f"Błąd operacji: {e}")
            if os.path.exists(os.path.abspath(destPath)):
                os.remove(os.path.abspath(destPath))




# -------------------------------
#                               |
#      Program flow control     |
#                               |
# -------------------------------
@app.command()
def generateKey(
    keyFilePath: Annotated[str , typer.Argument(help="Path where save key")], 
    size:Annotated[int, typer.Option("--size","-s",help="Size of the key in bytes")] = 32
)->bytes:
    '''
    Generate new key (default 32 bytes)
    '''
    
    key = os.urandom(size)
    with open(os.path.abspath("./" + keyFilePath), "wb") as f:
        f.write(key)
    
    return key
    
def readKey(keyFilePath:str)->bytes:
    '''
    Read key from file
    '''
    
    key = None
    with open(os.path.abspath(keyFilePath), "rb") as f:
        key = f.read()
        
    return key


@app.command()
def setSettings(
    algorithm: Annotated[str, typer.Option("--algorithm", "-a", help="Choose encryption algorithm (AES, AES128, AES256, SM4)")] = "AES256",
    mode: Annotated[str, typer.Option("--mode","-m", help="Choose mode for algorithm (CBC, CTR)")] = "CBC",
    padding: Annotated[str, typer.Option("--padding","-p", help="Choose padding (PKCS7, ANSIX923) None if CTR is choosen")] = "PKCS7",
    filePath:  Annotated[str,  typer.Option(help = "Where save settings")] = "./settings.json",
):

    settings = {
        "algorithm": algorithm, 
        "mode": mode, 
        "padding" : padding
    
    }
    
    avaliableAlgorithm = {'AES', 'AES128', 'AES256', 'SM4'}
    avaliableMode = {'CBC', 'CTR'}
    avaliablePadding = {'PKCS7', 'ANSIX923', 'None'}
    
    if algorithm not in avaliableAlgorithm:
        raise Exception("Wrong algorithm")
    
    if mode not in avaliableMode:
        raise Exception("Wrong mode")
    
    if padding not in avaliablePadding:
        raise Exception("Wrong padding")
    
    if mode == 'CTR':
        settings['padding'] = 'None'
    elif padding == 'None':
        raise Exception("Wrong padding")
    
    fileSettings = None
    try:
        fileSettings = os.path.abspath(filePath)
        with open(fileSettings, "w") as f:
            json.dump(settings,f)
        
        print("Settings saved !")
            
    except Exception as e:
        print(f'Error: {e}')
        if fileSettings is not None and os.path.exists(fileSettings):
            os.remove(fileSettings)

        
        
def loadSettings(filePath:str = "./settings.json"):
    
    algorithmList = {
        'AES'       : algorithms.AES,
        'AES128'    : algorithms.AES128,
        'AES256'    : algorithms.AES256,
        'SM4'       : algorithms.SM4
    }
    
    modesList = {
        'CBC': modes.CBC,
        'CTR': modes.CTR
    }
    
    paddingList = {
        'PKCS7'         : padding.PKCS7,
        'ANSIX923'      : padding.ANSIX923,
        'None'          : None
    }
        
    settings = None
    try:
        if filePath is None:
            raise FileNotFoundError()
            
        with open(os.path.abspath(filePath),"r") as f:
            settings = json.load(f)
            
    except Exception as e:
        if isinstance(e,FileNotFoundError):
            print("Settings not found, applaying default settings !")
        else:
            print(f'Error: {e}')
        
        return  algorithmList['AES256'], \
                modesList['CBC'], \
                paddingList['PKCS7']\
        
    print(settings)
    
    if settings['mode'] != 'CTR' and settings['padding'] == 'None':
        raise Exception("Wrong padding")
    
    return  (algorithmList[settings['algorithm']],
            modesList[settings['mode']],
            paddingList[settings['padding']])


@app.command()
def encryptFile(
    filePath: Annotated[str,  typer.Argument(help = "Source file to encrypt")], 
    keyPath:  Annotated[str,  typer.Argument(help = "Source key file")], 
    fileDest: Annotated[str,  typer.Option("--fileDest", "-fd", help="File path where encrypt file will be save",show_default=True)] = None,
    encrypt:  Annotated[bool, typer.Option("--encrypt/--decrypt", "-e/-d", help = "Chose bettwen encryption or decryption")] = True,
    settings: Annotated[str,  typer.Option("--settings", "-s", help="Path to file with encryption settings")] = None
)->None:
    '''
    Encrypt or decrypt file(filePath) using key(keyPath).
    if destination file (fileDest) is empty file will be replaced
    '''
    
    # Algorithms key and settings
    key = readKey(keyPath)
    algorithm, mode, padd = loadSettings(settings)
    
    x = FileEncryption()
    x.load_setting(key,algorithm,mode,padd)
    x.readSaveEncryptDecrypt(
        filePath = filePath,
        destPath = fileDest,
        encrypt  = encrypt
    )
    
    
@app.command()
def encryptDir(
    dirPath:  Annotated[str,  typer.Argument(help = "Source dir to encrypt")], 
    keyPath:  Annotated[str,  typer.Argument(help = "Source key file")], 
    dirDest:  Annotated[str,  typer.Option("--dirDest","-dd",help = "dir path where encrypt file will be save")] = None,
    encrypt:  Annotated[bool, typer.Option("--encrypt/--decrypt","-e/-d", help = "Chose bettwen encryption or decryption")] = True,
    settings: Annotated[str,  typer.Option("--settings","-s", help="Path to file with encryption settings")] = None
)->None:
    '''
    Encrypt or decrypt whole dir (dirPath) using key(keyPath).
    if destination dir (dirDest) is empty files will be replaced
    '''
    
    key = readKey(keyPath)
    algorithm, mode, padd = loadSettings(settings)
    
    x = FileEncryption()
    x.load_setting(key,algorithm,mode,padd)
    
    abs_dirPath = os.path.abspath(dirPath)
    
    if dirDest is not None:
        abs_dirDest = os.path.abspath(dirDest)
        if not os.path.exists(abs_dirDest):
            os.makedirs(abs_dirDest)
    
    # Przechodzenie rekurencyjne przez katalogi
    for root, dirs, files in os.walk(abs_dirPath):
        for file in files:
            input_file_path = os.path.join(root, file)
            
            if dirDest is None:
                output_file_path = None
            else:
                # Obliczanie ścieżki względnej, aby zachować strukturę drzewa
                rel_path = os.path.relpath(root, abs_dirPath)
                
                if rel_path == ".":
                    target_dir = abs_dirDest
                else:
                    target_dir = os.path.join(abs_dirDest, rel_path)
                
                # Tworzenie podkatalogu w folderze docelowym, jeśli nie istnieje
                if not os.path.exists(target_dir):
                    os.makedirs(target_dir)
                    
                output_file_path = os.path.join(target_dir, file)
            
            x.readSaveEncryptDecrypt(
                input_file_path, 
                output_file_path,
                encrypt = encrypt
            )


if __name__ == "__main__":
    app()
