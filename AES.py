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
    image_ext = None # Extensión del archivo de la imagen

    # Credenciales del cifrado
    key = None 
    iv = None
    mode = AES.MODE_ECB

    def __init__(self):
        pass

    # Establcemos la ruta y obtenemos la información de ella, como la extensión del archivo y su nombre.
    def setImagePath(self, ruta: str):
        self.url = ruta
        aux = ruta.split("/")
        name = aux[-1].split(".")
        self.image_ext = name[-1]
        self.image_name = name[0]
        self.path = self.url.replace(aux[-1], "") # Sacamos el path solo de la ruta entera

    #Definimos la key y el IV para la encriptación.
    # La key es el valor más importante para guiar las permutaciones del algorítmo y el IV, o 
    # input vector es un complemento a esta seguridad. Se agrega a la clave, similar al complemento
    # de un salt al momento de realizar un hash.
    def setKey(self, key: bytes):
        self.key = pad(key, 16)

    def setIv(self, iv: bytes):
        self.iv = pad(iv, 16)

    # Como AES tiene muchos modos, se define con un string.
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

    #Función de encriptación
    def encrypt(self):
        # Si se detectó un archivo
        if(self.url != None and self.key != None):
            print("Cifrando...")
            # Se utiliza la librería Pillow para abrir la imagen y la covierte a un arreglo usando numpy
            img = Image.open(self.url)
            self.image = np.array(img)
            self.image_size = img.size
            # Crea el url para la nueva imagene
            new_url = self.path + self.image_name + "_e" + self.getMode() + "." + self.image_ext

            cipher = None
            # En el modo ECB no se usa un IV, por lo que si no es de ese método no se agrega al new
            
            if(self.getMode() != "ECB"):
                cipher = AES.new(self.key, self.mode, iv=self.iv)
            else:
                cipher = AES.new(self.key, self.mode)

            # Se cifra haciendo uso de la librería pycryptodome
            ct_bytes = cipher.encrypt(
                pad(
                    self.image.tobytes(),
                    AES.block_size,
                )
            )

            # Luego se vuelve a utilizar la librería numpy y Pillow para obtener los datos
            # desde un buffer y se vuelve a crear una imagen. La cual se guarda con el url creado.
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

    # Similar al encrypt, pero utiliza la función cypher.decrypt.
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
        # Obtenemos las credenciales para encriptación
        key_str = input("Ingrese la clave de 16 bytes: ")
        iv_str = input("Ingrese el IV de 16 bytes: ")
        # Formateamos la información para que esté de acuerdo a lo requerido
        key = key_str.encode('utf-8')[:16]
        iv = iv_str.encode('utf-8')[:16]
        # Creamos el objeto cipher, con el que se obtiene toda la información y se realizan todas las funciones.
        cipher = AESImageCipher()
        # Obtenemos el path y agregamos toda la información al objeto
        imagePath = input("Ingrese el path de la imagen: ")
        cipher.setImagePath(imagePath)
        cipher.setKey(key)
        cipher.setIv(iv)
        # Establecemos el método de encriptación
        cipher.setMode("CBC")
        option = input("Seleccione la opción que quiera\n1. Encriptar\n2. Desencriptar\n0. Salir\n")
        # Menú de opciones
        if(option == "1"):
            cipher.encrypt()
        elif(option == "2"):
            cipher.decrypt()

        option = input("Quiere continuar?\n1. Sí\n0. No\n")