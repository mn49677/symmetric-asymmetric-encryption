import re

class Convert:
    # Pretvorba formatiranog teksta u rječnik ključ - vrijednost
    def TxtToDict(txtPath):
        file = open(txtPath)
        s = file.read()
        start = s.find("---BEGIN OS2 CRYPTO DATA---") + len("---BEGIN OS2 CRYPTO DATA---")
        end = s.find("---END OS2 CRYPTO DATA---")
        pairs = s[start:end].split('\n\n')
        dict = {}
        for pair in pairs:
            if pair == "":
                continue
            dict[pair.split(':')[0]] = pair.split(':')[1].replace('\n', '').replace(' ', '')
            # print(pair.split(':')[0] +" : "+ dict[pair.split(':')[0]])
        return dict
    # Kreiranje formatirane datoteke iz rječnika
    def DictToStr(dict):
        s = "---BEGIN OS2 CRYPTO DATA---\n"
        for key in dict.keys():
            s = s + key + ":\n    " + dict[key] + "\n\n"
        s += "---END OS2 CRYPTO DATA---"
        return s

