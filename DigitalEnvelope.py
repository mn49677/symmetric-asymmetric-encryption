from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import DES3, AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import binascii, os
from HelpFunction import HelpFunctions

class DigitalEnvelope:

    # DE ENCRYPT - RSA i simetrični kriptosustav po izboru, prima novi argument simetricCryptosystem (string 'AES' ili '3DES')
    def encrypt(msg, key, n, e, mode, iv, simetricCryptosystem) -> bytes:
        if simetricCryptosystem == 'AES':
            return DigitalEnvelope.encryptRSAAES(msg, key, n, e, mode, iv)
        elif simetricCryptosystem == 'DES3':
            return DigitalEnvelope.encryptRSADES3(msg, key, n, e, mode, iv)

    # DE DECRYPT - RSA i simetrični kriptosustav po izboru, prima novi argument simetricCryptosystem (string 'AES' ili '3DES')
    def decrypt(C1, C2, n, e, d, mode, iv, simetricCryptosystem) -> bytes:
        if simetricCryptosystem == 'AES':
            return DigitalEnvelope.decryptRSAAES(C1, C2, n, e, d, mode, iv)
        elif simetricCryptosystem == 'DES3':
            return DigitalEnvelope.decryptRSADES3(C1, C2, n, e, d, mode, iv)

    # DE - RSA i DES3 enkripcija
    def encryptRSADES3(msg, key, n, e, mode, iv):
        C1 = DigitalEnvelope.encryptDES3(key, mode, msg, iv)
        C2 = DigitalEnvelope.encryptRSA(n, e, key)
        return (C1, C2)
    
    # DE - RSA i DES3 dekripcija
    def decryptRSADES3(C1, C2, n, e, d, mode, iv):
        key = DigitalEnvelope.decryptRSA(n, e, d, C2)
        return DigitalEnvelope.decryptDES3(key, mode, C1, iv)

    # DE - RSA i AES enkripcija
    def encryptRSAAES(msg, key, n, e, mode, iv):
        C1 = DigitalEnvelope.encryptAES(key, None, mode, msg, iv)
        C2 = DigitalEnvelope.encryptRSA(n, e, key)
        # print((C1, C2))
        return (C1, C2)
    
    # DE - RSA i AES dekripcija
    def decryptRSAAES(C1, C2, n, e, d, mode, iv):
        key = DigitalEnvelope.decryptRSA(n, e, d, C2)
        return DigitalEnvelope.decryptAES(key, None, mode, C1, iv)
    
    # enkripcija pomoću RSA kriptosustava
    def encryptRSA(n, e, msg):
        pubKey1 = RSA.construct((n, e))
        encryptor = PKCS1_OAEP.new(pubKey1)
        encrypted = encryptor.encrypt(msg)
        return encrypted

    # dekripcija pomoću RSA kriptosustava
    def decryptRSA(n, e, d, msg):
        pubKey2 = RSA.construct((n, e, d))
        decryptor = PKCS1_OAEP.new(pubKey2)
        decrypted = decryptor.decrypt(msg)
        return decrypted

    # enkripcija pomoću DES3 simetričnog kriptosustava
    def encryptDES3(key, mode, msg, iv):
        cipher = None
        # print(key)
        if mode == 'ECB':
            cipher = DES3.new(key, HelpFunctions.getMode(mode))
        else:
            cipher = DES3.new(key, HelpFunctions.getMode(mode), iv)
        return cipher.encrypt(msg)
    
    # dekripcija pomoću DES3 simetričnog kriptosustava
    def decryptDES3(key, mode, msg, iv):
        cipher = None
        if mode == 'ECB':
            cipher = DES3.new(key, HelpFunctions.getMode(mode))
        else:
            cipher = DES3.new(key, HelpFunctions.getMode(mode), iv)
        return cipher.decrypt(msg)
    
    # enkripcija pomoću AES kriptosustava
    def encryptAES(key, keySize, mode, msg, iv):
        cipher = None
        if mode == 'ECB':
            cipher = AES.new(key, HelpFunctions.getMode(mode))
        else:
            cipher = AES.new(key, HelpFunctions.getMode(mode), iv)
        return cipher.encrypt(msg)
    
    # dekriptiranje pomoću AES kriptosustava
    def decryptAES(key, keySize, mode, msg, iv):
        cipher = None
        if mode == 'ECB':
            cipher = AES.new(key, HelpFunctions.getMode(mode))
        else:
            cipher = AES.new(key, HelpFunctions.getMode(mode), iv)
        return cipher.decrypt(msg)


# MAIN PROGRAM


# ------------------------------------------------------------------------------------ UPIS POSTAVKI ZA KRIPTOSUSTAVE

# # Upis kriptosustava, ključa, načina kriptiranja za simetrični kriptosustav
# cryptosystem = input("Upišite simetrični kriptosustav ('DES3' ili 'AES'): ")
# key = ""
# while (len(key) != 16 or len(key) != 24 or len(key) != 32) and (cryptosystem == "AES"):
#     try:
#         key = input("Upiši ključ sa duljinom od 16 (128b), 24 (192b) ili 32 (256b) znaka: ")
#     except:
#         print("Znakovi ne predstavljaju broj!")
# while (len(key) != 16) and (cryptosystem == "DES3"):
#     try:
#         key = input("Upiši ključ sa duljinom od 16 (128b): ")
#     except:
#         print("Znakovi ne predstavljaju broj!")

# # Način rada kriptosustava
# mode = input("Upišite još način rada kriptosustava: ")

# # Poruka koja se želi poslati
# msg = input("Upišite poruku za kriptiranje: ")


# ------------------------------------------------------------------------------------ 


# ------------------------------------------------------------------------------------ ASIMETRIČNI KRIPTOSUSTAV RSA
# Enkripcija (šaljem (n, e) i msg)
# POŠILJATELJ
# e - javni ključ
# n - modulus
# encrypted = DigitalEnvelope.encryptRSA(pubKey.n, pubKey.e, msg)

# Dekripcija (šaljem encrypted i (n, e, d))
# PRIMATELJ
# d - privatni eksponent
# e - javni eksponent
# n - modulus
# DigitalEnvelope.decryptRSA(keyPair.n, keyPair.e, keyPair.d, encrypted)

# ------------------------------------------------------------------------------------ SIMETRIČNI KRIPTOSUSTAVI DES3, AES
# DES3
# print()
# iv = Random.new().read(DES3.block_size)
# encrypted = DigitalEnvelope.encryptDES3(b"kljucodsedambajt", "CFB", msg, iv)
# print("DES3 Decrypted: ")
# print(DigitalEnvelope.decryptDES3(b"kljucodsedambajt", "CFB", encrypted, iv))

# AES
# print()
# iv = Random.new().read(AES.block_size)
# encrypted = DigitalEnvelope.encryptAES(b"kljucodsedambajt", None, "CFB", msg, iv)
# print("AES Decrypted: ")
# print(DigitalEnvelope.decryptAES(b"kljucodsedambajt", None, "CFB", encrypted, iv))



# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# # Upis poruke za slanje
# msg = b'A message for encryption with length to it because bla bla bla'

# # Upis veličine ključa za asimetrični kriptosustav
# keySize = None
# while not keySize:
#     try:
#         keySize = int(input("Upiši veličinu ključa RSA: "))
#     except ValueError:
#         print ("Znakovi ne predstavljaju broj!")

# keyPair = RSA.generate(keySize)
# pubKey = keyPair.publickey()
# pubKeyPEM = pubKey.exportKey()
# privKeyPEM = keyPair.exportKey()

# # Upis podataka za DE (digitalnu omotnicu)
# simetricCryptosystem = input("Upišite simetrični kriptosustav('AES' ili 'DES3'): ")
# iv = None
# if simetricCryptosystem == 'DES3': 
#     iv = Random.new().read(DES3.block_size)
# elif simetricCryptosystem == 'AES':
#     iv = Random.new().read(AES.block_size)

# # Način rada kriptosustava
# mode = input("Upišite način rada kriptosustava('ECB' - radi, 'CBC' - radi, 'OFB' - radi, 'CFB' - radi, 'CTR'): ")

# # Digitalna omotnica - provjera rada za DES3 i AES
# C1, C2 = DigitalEnvelope.encrypt(pad(msg, 32), b"kljucodsedambajt", pubKey.n, pubKey.e, mode, iv, simetricCryptosystem)
# print("Digitalna omotnica dekripcija (" + simetricCryptosystem + "):")
# encrypted = DigitalEnvelope.decrypt(C1, C2, keyPair.n, keyPair.e, keyPair.d, mode, iv, simetricCryptosystem)

# print(unpad(encrypted, AES.block_size))


# --Problemi--
# Ne radi CTR
# --Dodati-- -> DODANO, DigitalEnvelopeText.py
# Implementaciju sa tekstualnim datotekama