from DigitalEnvelope import DigitalEnvelope
from Convert import Convert
from Crypto.Util.Padding import pad, unpad
import base64
from HelpFunction import HelpFunctions
from Crypto.Cipher import DES3, AES
from Crypto.PublicKey import RSA
from Crypto import Random

# klasa koja prima tekstualne datoteke kao ulazne vrijednosti
class DigitalEnvelopeText:

    def encrypt(msg, publicKey, secretKey, mode) -> bytes:
        publicKeyDict = Convert.TxtToDict(publicKey)
        secretKeyDict = Convert.TxtToDict(secretKey)
        n = int(publicKeyDict['Modulus'], 16)
        e = int(publicKeyDict['Public exponent'], 16)
        iv = DigitalEnvelopeText.convertToB(secretKeyDict['Initialization vector'])
        simetricCryptosystem = secretKeyDict['Method']
        C1, C2 = DigitalEnvelope.encrypt(msg, DigitalEnvelopeText.convertToB(secretKeyDict['Secret key']), n, e, mode, iv, simetricCryptosystem)

        methods = secretKeyDict['Method'] + "\n    " + publicKeyDict['Method']
        keyLengths = None
        if secretKeyDict['Method'] == 'DES3':
            keyLengths = publicKeyDict['Key length']
        else:
            keyLengths = secretKeyDict['Key length'] + "\n    " + publicKeyDict['Key length']
        dict = {
            'Description':'Envelope',
            'File name':'DE.txt',
            'Method':methods,
            'Key length':keyLengths,
            'Envelope data':base64.b64encode(C1).decode("utf-8"),
            'Envelope crypt key':base64.b64encode(C2).decode("utf-8"),
            'Initialization vector': secretKeyDict['Initialization vector']
        }
        # print(Convert.DictToStr(dict))
        HelpFunctions.strToTxt(Convert.DictToStr(dict), "DE") # kreira se datoteka DE.txt
        return C1, C2
        
    def decrypt(de, publicKey, privateKey, mode) -> bytes:
        deDict = Convert.TxtToDict(de)
        publicKeyDict = Convert.TxtToDict(publicKey)
        privateKeyDict = Convert.TxtToDict(privateKey)
        C1 = base64.b64decode( deDict['Envelope data'].encode('utf-8') )
        C2 = base64.b64decode( deDict['Envelope crypt key'].encode('utf-8') )
        n = int(privateKeyDict['Modulus'], 16)
        e = int(publicKeyDict['Public exponent'], 16)
        d = int(privateKeyDict['Private exponent'], 16)
        simetricCryptosystem = deDict['Method'][0:-3]
        # print((C1, C2, n, e, d, mode, bytes.fromhex(deDict['Initialization vector']), simetricCryptosystem))
        # print(simetricCryptosystem)
        return DigitalEnvelope.decrypt(C1, C2, n, e, d, mode, bytes.fromhex(deDict['Initialization vector']), simetricCryptosystem)

    def convertToB(value) -> bytes:
        return bytes.fromhex(value)


# keyPair = RSA.generate(1024)
# pubKey = keyPair.publickey()
# pubKeyPEM = pubKey.exportKey()
# privKeyPEM = keyPair.exportKey()
# print(hex(pubKey.n))
# print(hex(pubKey.e))
# print(hex(keyPair.d))

# ---------------------------------------------------------------------------------------------------------------------------------------
# Unos podataka i postavki enkripcije i dekripcije / kreiranje tekstualnih datoteka

# Generiranje asimetričnih ključeva (VELIČINA KLJUČA)
# Odabir simetričnog kriptosustava (AES ili DES3)
# Generiranje simetričnih ključeva (odabir VELIČINE KLJUČA)
# Odabir načina kriptiranja
# Upis poruke za kriptirati i poslati

# ---------------------------------------------------------------------------------------------------------------------------------------
# ENKRIPTIRANJE poruke
# print("IV:"+Random.new().read(DES3.block_size).hex())
# msg = 'poruka za kriptirati'
# DigitalEnvelopeText.encrypt(pad(b'poruka za kriptirati', 128), "RSA_publicKey.txt", "DES_secretKey.txt", "CBC")
# print("-----------------------")
# print("Originalna poruka:   " + msg)
# print("-----------------------")
# # ---------------------------------------------------------------------------------------------------------------------------------------
# # DEKRIPTIRANJE poruke
# decrypted = DigitalEnvelopeText.decrypt("DE.txt", "RSA_publicKey.txt", "RSA_privateKey.txt", "CBC")
# print("Dekriptirana poruka: "+unpad(decrypted, 128).decode('utf-8')) # prikaz bytes poruke
# print("-----------------------")
# ---------------------------------------------------------------------------------------------------------------------------------------
