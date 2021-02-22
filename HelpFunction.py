from Crypto.Cipher import AES
from Crypto.Hash import SHA384, SHA512, SHA3_384, SHA3_512
import os
from Crypto import Random
from Crypto.PublicKey import RSA

class HelpFunctions:
    def getMode(modeString):
        if modeString == 'ECB': # Ne treba IV
            return AES.MODE_ECB
        elif modeString == 'CBC': # Treba IV
            return AES.MODE_CBC
        elif modeString == 'OFB': # Treba IV
            return AES.MODE_OFB
        elif modeString == 'CFB': # Treba IV
            return AES.MODE_CFB
        elif modeString == 'CTR': # Treba IV
            return AES.MODE_CTR
        return AES.MODE_CBC # defaultno

    def getHash(msg, hashString) -> bytes:
        if hashString == 'SHA384':
            hash = SHA384.new()
            hash.update(msg)
            return hash.digest()
        if hashString == 'SHA512':
            hash = SHA384.new()
            hash.update(msg)
            return hash.digest()
        if hashString == 'SHA3_384':
            hash = SHA384.new()
            hash.update(msg)
            return hash.digest()
        if hashString == 'SHA3_512':
            hash = SHA384.new()
            hash.update(msg)
            return hash.digest()
    
    def getHashLength(hashString) -> str:
        if hashString == 'SHA384':
            return hex(384)
        if hashString == 'SHA512':
            return hex(512)
        if hashString == 'SHA3_384':
            return hex(384)
        if hashString == 'SHA3_512':
            return hex(512)
    
    def strToTxt(str, txtname) -> None:
        file = open(txtname+".txt", "w")
        file.write(str)

    def generateTxtSimetric(sc, keyLength, block_size, nameExt):
        keyLength = int(keyLength)/8
        keyLengthInt = int(keyLength)
        # print(keyLength)
        key = os.urandom(int(keyLength)).hex()
        iv = Random.new().read(block_size).hex()
        str = "---BEGIN OS2 CRYPTO DATA---\nDescription:\n    Secret key\n\nMethod:\n    " + sc + "\n\nSecret key:\n    " + key +"\n\nInitialization vector:\n    " + iv + "\n\nKey length:\n    "+ hex(keyLengthInt)[2:] +"---END OS2 CRYPTO DATA---"
        file = open(sc+"_secretKey"+nameExt+".txt", "w")
        file.write(str)
        return sc+"_secretKey"+nameExt+".txt"
    def generateTxtAsimetric(keyLength, nameExt):
        keys = RSA.generate(int(keyLength))
        keyLength = hex(int(keyLength))
        strPu = "---BEGIN OS2 CRYPTO DATA---\nDescription:\n    Private key\n\nMethod:\n    " + "RSA" + "\n\nKey length:\n    " + "0"+keyLength[2:] + "\n\nModulus:\n    "+ hex(keys.n)[2:] + "\n\nPublic exponent:\n    " + "0" + hex(keys.e)[2:] + "\n---END OS2 CRYPTO DATA---"
        strPr =  "---BEGIN OS2 CRYPTO DATA---\nDescription:\n    Public key\n\nMethod:\n    " + "RSA" + "\n\nKey length:\n    " + "0"+keyLength[2:] + "\n\nModulus:\n    "+ hex(keys.n)[2:] + "\n\nPrivate exponent:\n    " + hex(keys.d)[2:] + "\n---END OS2 CRYPTO DATA---"
        open("RSA_publicKey"+nameExt+".txt", "w").write(strPu)
        open("RSA_privateKey"+nameExt+".txt", "w").write(strPr)
        return strPu+"\n\n"+strPr
# print(HelpFunctions.generateTxtSimetric("AES", 64, 8))
# print(HelpFunctions.generateTxtAsimetric(2048, "C"))