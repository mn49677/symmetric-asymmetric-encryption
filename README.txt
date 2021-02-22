1. OS = macOS 10.15.4
2. Glavne datoteke: 
    DigitalEnvelope.py - ostvarena digitalna omotnica no ulazne varijable nisu tekstualne datoteke poput onih na stranici labosa već stringovi intovi hexovi
    DigitalEnvelopeTxt.py - parsira tekstualne datoteke i vrijednosti iz njih šalje u DigitalEnvelope klasu u datoteci DigitalEnvelope.py
    DigitalSignature.py - digitalni potpis koji direktno prima tekstualne datoteke
    DigitalStamp.py - digitalni pečat, prima i parsira tekstualnu datoteku i koristi digitalnu omotnicu iz datoteke DigitalEnvelopeTxt.py 
        i digitalni potpis iz DigitalSignature.py i šalje te vrijednosti primatelju
3. Tekstualne datoteke koje su pripremljene nisu obvezne jer Test.py prije svega izgenerira sve potrebne tekstualne datoteke koje sadrže ključeve veličina
    koje su definirane na početku kad se pokrene program (kroz input u bashu)
4. Test.py provodi test tako da enkriptira poruku pa ju dekriptira (primjera radi digitalna omotnica) i onda ispisuje vrijednosti izlaza
5. Prije svake funkcije encrypt ili decrypt sam stavio varijable kojima "ima pristup" taj korisnik (primatelj ili posiljatelj) npr. ako je digitalni potpis
    u pitanju onda pošiljatelj ima svoj privatni i javni ključ a primatelj poruke ima samo njegov javni
6. PyInstaller s kojim se kreira pokretačka datoteka ima specifični problem (na macOSu) da ne includea neki dio librarya za SHA i iz tog razloga javlja 
    sljedeći error kad pokretano na taj način: "AttributeError: dlsym(0x7fd57ef54fb0, SHA1_init): symbol not found" te iz tog razloga ću kreirati samo exe
    za windows a ne linux os -> NE MOGU POSLATI, PREVELIKI FILE OD 6.8 MB