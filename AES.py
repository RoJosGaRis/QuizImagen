from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode


class AESImageCipher:
    # Image
    url = None  # Ruta completa de la imagen
    image = None  # Objeto de la imagen
    image_name = None  # nombre de imagen sin extensiones
    path = None  # Ruta de la carpeta de la imagen
    image_size = None  # Resolucion de la iamgen
    image_ext = None

    # Cipher
    key = None
    iv = None
    mode = AES.MODE_ECB

    def __init__(self):
        pass

    def setImagePath(self, ruta: str):
        self.url = ruta
        aux = ruta.split("/")
        name = aux[-1].split(".")
        self.image_ext = name[-1]
        self.image_name = name[0]
        self.path = self.url.replace(aux[-1], "")

    def setKey(self, key: bytes):
        self.key = pad(key, 16)

    def setIv(self, iv: bytes):
        self.iv = pad(iv, 16)

    def setMode(self, modo: str):
        if(modo == 'ECB'):
            self.mode = AES.MODE_ECB
        elif(modo == 'CBC'):
            self.mode = AES.MODE_CBC
        elif(modo == 'CFB'):
            self.mode = AES.MODE_CFB
        elif(modo == 'OFB'):
            self.mode = AES.MODE_OFB
        else:
            print("Mode not recognized")

    def getMode(self):
        if(self.mode == AES.MODE_ECB):
            return "ECB"
        elif(self.mode == AES.MODE_CBC):
            return "CBC"
        elif(self.mode == AES.MODE_CFB):
            return "CFB"
        elif(self.mode == AES.MODE_OFB):
            return "OFB"
        else:
            return None

    def encrypt(self):
        if(self.url != None and self.key != None):
            print("Cifrando...")
            img = Image.open(self.url)
            self.image = np.array(img)
            self.image_size = img.size
            new_url = self.path + self.image_name + "_e" + self.getMode() + "." + self.image_ext

            cipher = None
            if(self.getMode() != "ECB"):
                cipher = AES.new(self.key, self.mode, iv=self.iv)
            else:
                cipher = AES.new(self.key, self.mode)

            ct_bytes = cipher.encrypt(
                pad(
                    self.image.tobytes(),
                    AES.block_size,
                )
            )
            img_data = np.frombuffer(ct_bytes)

            image_nva = Image.frombuffer(
                "RGB",
                self.image_size,
                img_data
            )
            image_nva.save(
                new_url
            )
            print("Cifrado")

    def decrypt(self):
        if(self.url != None and self.key != None):
            print("Decifrando...")
            img = Image.open(self.url)
            self.image = np.array(img)
            self.image_size = img.size

            new_url = self.path + self.image_name + "_d" + self.getMode() + "." + self.image_ext
            cipher = None
            if(self.getMode() != "ECB"):
                cipher = AES.new(self.key, self.mode, iv=self.iv)
            else:
                cipher = AES.new(self.key, self.mode)

            aux = self.image.tobytes()
            pt = cipher.decrypt(
                aux
            )

            img_data = np.frombuffer(pt)

            Image.frombuffer(
                "RGB",
                self.image_size,
                img_data
            ).save(
                new_url
            )


if __name__ == "__main__":
    option = 1
    while option != 0:
        key_str = input("Ingrese la clave de 16 bits: ")
        iv_str = input("Ingrese el IV de 16 bits: ")
        
        key = key_str.encode('utf-8')[:16]
        iv = iv_str.encode('utf-8')[:16]

        cipher = AESImageCipher()
        imagePath = input("Ingrese el path de la imagen: ")
        cipher.setImagePath(imagePath)
        cipher.setKey(key)
        cipher.setIv(iv)
        cipher.setMode("CBC")
        option = input("Seleccione la opción que quiera\n1. Encriptar\n2. Desencriptar\n0. Salir\n")
    
        if(option == "1"):
            cipher.encrypt()
        elif(option == "2"):
            cipher.decrypt()

        option = input("Quiere continuar?\n1. Sí\n0. No\n")