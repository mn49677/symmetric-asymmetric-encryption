# Main program (za pokrenuti)
# Sadrži sve testove za labos
# Za svaku klasu postoje još zakomentirani testovi unutar datoteke

from DigitalEnvelopeText import DigitalEnvelopeText
from DigitalSignature import DigitalSignature
from DigitalStamp import DigitalStamp
from HelpFunction import HelpFunctions
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES3
import os

# --------------------------------------------------------------------------------------------------
# Simetrični kriptosustav: AES i 3-DES. 
sc = input("Upišite simetrični kriptosustav (string 'AES' ili 'DES3'): ")
# Ponuditi na izbor sve moguće veličine ključeva za svaki algoritam
keyLengthSC = None
block_size = None
if sc == 'AES':
    keyLengthSC = input("Za AES upišite veličinu ključa (128, 192 i 256): ")
    block_size = AES.block_size
else:
    keyLengthSC = 192
    block_size = DES3.block_size
# Najmanje dva načina kriptiranja (ECB, CBC, OFB, CFB, CTR, ...)
mode = input("Odaberite način kriptiranja (CBC, CFB): ")
# Odaberite RSA veličinu ključa
keyLengthRSA = input("Odaberite duljinu ključa za RSA asimetrični kriptosustav (1024, 2048, 3072): ")
# Odaberite funkciju za izračunavanje sažetka (hash)
hash = input("Odaberite funkciju za izračun sažetka (SHA384 ili SHA512 ili SHA3_384 ili SHA3_512): ")
# Poruka za slanje
msg = input("Upišite poruku koja se šalje: ")
# --------------------------------------------------------------------------------------------------
# Print svih postavki
print("------------------------------------------")
if sc == 'AES':
    print("Simetrični kriptosustav: " + sc + " "+ keyLengthSC)

else:
    print("Simetrični kriptosustav: " + sc)
print("Način kriptiranja: " + mode)
print("Asimetrični kriptosustav: " + "RSA " + keyLengthRSA)
print("Hash funkcija: " + hash)
print("------------------------------------------")
# --------------------------------------------------------------------------------------------------
# Kreiranje datoteka
HelpFunctions.generateTxtSimetric(sc, keyLengthSC, block_size, "DO") # digitalna  omotnica datoteka
HelpFunctions.generateTxtAsimetric(keyLengthRSA, "DO") # digitalna omotnica datoteka
HelpFunctions.generateTxtAsimetric(keyLengthRSA, "DS") # digitalni potpis datoteka
simetricKey = HelpFunctions.generateTxtSimetric(sc, keyLengthSC, block_size, "DStamp") # digitalni pečat simetrični kriptosustav po ulazu
HelpFunctions.generateTxtAsimetric(keyLengthRSA, "A")
HelpFunctions.generateTxtAsimetric(keyLengthRSA, "B")

# --------------------------------------------------------------------------------------------------

# Digitalna omotnica
print("------------------------------------------")
print("------------Digitalna omotnica------------")
# Enkripcija (POŠILJATELJ)
publicKey = "RSA_publicKeyDO.txt"
secretKey = "DES3_secretKeyDO.txt"
if sc == "AES":
    secretKey = "AES_secretKeyDO.txt"
DigitalEnvelopeText.encrypt(pad(bytes(msg, 'utf-8'), 128), publicKey, secretKey, mode)

# Dekripcija (PRIMATELJ)
de = "DE.txt"
publicKey = "RSA_publicKeyDO.txt"
privateKey = "RSA_privateKeyDO.txt"
decrypted = DigitalEnvelopeText.decrypt(de, publicKey, privateKey, mode)
# print(decrypted)
print("Dekriptirana poruka: " + str(unpad(decrypted, 128).decode('utf-8')))

# --------------------------------------------------------------------------------------------------
# Digitalni potpis
print("------------------------------------------")
print("-------------Digitalni potpis-------------")
# Enkripcija (POŠILJATELJ)
privateKey = "RSA_privateKeyDS.txt"
DigitalSignature.sign(bytes(msg, 'utf-8'), privateKey, hash)

# Dekripcija (PRIMATELJ)
publicKey = "RSA_publicKeyDS.txt"
ds = "DS.txt"
print("Digitalni potpis: " + str(DigitalSignature.check(publicKey, ds)))

# --------------------------------------------------------------------------------------------------
# Digitalni pečat
print("------------------------------------------")
print("-------------Digitalni pečat--------------")
# Enkripcija (POŠILJATELJ A)
privateKeyA = "RSA_privateKeyA.txt"
publicKeyA  = "RSA_publicKeyA.txt"
publicKeyB  = "RSA_publicKeyB.txt"
secretKey   = simetricKey
C1, C2, C3 = DigitalStamp.create(pad(bytes(msg, 'utf-8'), 128), publicKeyB, privateKeyA, secretKey, mode, hash)

# Dekripcija (PRIMATELJ B)
privateKeyB = "RSA_privateKeyB.txt"
publicKeyA  = "RSA_publicKeyA.txt"
publicKeyB  = "RSA_publicKeyB.txt"
msg, valid = DigitalStamp.open(C1, C2, C3, privateKeyB, publicKeyA, publicKeyB, mode)
print("Primatelj je primio: " + str(unpad(msg, 128).decode('utf-8')) + "\n" + "Autentično i sačuvan integritet: " + str(valid))
print("------------------------------------------")