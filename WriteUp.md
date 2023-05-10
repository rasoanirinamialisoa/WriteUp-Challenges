
## _WriteUpChallenge_



# I° FTP Authentification
 1. Démarrage du challenge
 2. Obtention du fichier ch1.pcap
 3. Analyse du paquet dans Wireshark
 4. Filtre du trafique par le protocole FTP
 6. Detection d'utilisateur et de mot de passe:
 

> '4.216600 10.20.144.150 → 10.20.144.151 FTP 81 Request: USER cdts3500'
> '4.217350 10.20.144.151 → 10.20.144.150 FTP 91 Response: 331 Enter password.'
>  '4.217630 10.20.144.150 → 10.20.144.151 TCP 66 35974 → 21 [PSH, ACK] Seq=16 Ack=114 Win=32648 Len=0 TSval=1657564500 TSecr=1657394000'
> '11 7.639420 10.20.144.150 → 10.20.144.151 FTP 81 Request: PASS cdts3500'

# II° TELNET Authentification

1. Démarrage du challenge
2. Obtention du fichier ch2.pcap
3. Analyse du paquet dans Wireshark
4. Filtre du trafique par le protocole TELNET
5. Selection de tous les filtres TELNET
6. Follow ----> TCP stream
7. Detection de mot de passe dans le contenue

> ........... ..!.."..'.....#..%..%........... ..!..".."........P. ....".....b........b....	B.
> ........................"......'.....#..&..&..$..&..&..$.. .....#.....'........... .9600,9600....#.bam.zing.org:0.0....'..DISPLAY.bam.zing.org:0.0......xterm-color.............!.............."............
> OpenBSD/i386 (oof) (ttyp1)
> login: .."........"ffaakkee
> .
> Password:user
> .
> Last login: Thu Dec  2 21:32:59 on ttyp1 from bam.zing.org

# III°Twitter Authentification
1. Démarrage du challenge
2. Obtention du fichier ch3.pcap
3. Analyse du paquet dans Wireshark
4. Détection d'une seule ligne au protocole HTTP
6. Follow ----> TCP stream
7. Detection de mot de passe dans le contenue

> GET /statuses/replies.xml HTTP/1.1\r\n
> User-Agent: CFNetwork/330\r\n
> Cookie: _twitter_sess=BAh7CDoJdXNlcjA6B2lkIiVmZGQ2ODc5MTMwMWFhOTFiMWExZDViZmQwMGEz%250AOWNkMyIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7AA%253D%253D--ea12e7bc090d05202cd7e3f972c2b4414a97f657\r\n
> Cookie pair: _twitter_sess=BAh7CDoJdXNlcjA6B2lkIiVmZGQ2ODc5MTMwMWFhOTFiMWExZDViZmQwMGEz%250AOWNkMyIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7AA%253D%253D--ea12e7bc090d05202cd7e3f972c2b4414a97f657
> Accept: */*\r\n
> Accept-Language: en-us\r\n
> Accept-Encoding: gzip, deflate\r\n
> Authorization: Basic dXNlcnRlc3Q6cGFzc3dvcmQ=\r\n
> Credentials: usertest:********
> Connection: keep-alive\r\n
> Host: twitter.com\r\n
  
# IV°ETHERNET Trame
1. Démarrage de challenge
2. Obtention de fichier ch12.txt avec le contenue ci-dessous :

> 00 05 73 a0 00 00 e0 69 95 d8 5a 13 86 dd 60 00
00 00 00 9b 06 40 26 07 53 00 00 60 2a bc 00 00
00 00 ba de c0 de 20 01 41 d0 00 02 42 33 00 00
00 00 00 00 00 04 96 74 00 50 bc ea 7d b8 00 c1
d7 03 80 18 00 e1 cf a0 00 00 01 01 08 0a 09 3e
69 b9 17 a1 7e d3 47 45 54 20 2f 20 48 54 54 50
2f 31 2e 31 0d 0a 41 75 74 68 6f 72 69 7a 61 74
69 6f 6e 3a 20 42 61 73 69 63 20 59 32 39 75 5a
6d 6b 36 5a 47 56 75 64 47 6c 68 62 41 3d 3d 0d
0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 49 6e 73
61 6e 65 42 72 6f 77 73 65 72 0d 0a 48 6f 73 74
3a 20 77 77 77 2e 6d 79 69 70 76 36 2e 6f 72 67
0d 0a 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d
0a

3. Décodage du code hexadecimale via le site : https://simplycalc.com/base16-decode.php
4. Resulat du décryptage : 

> s àiØZÝ`@&S`*¼ºÞÀÞ AÐB3tP¼ê}¸Á×áÏ 
	>i¹¡~ÓGET / HTTP/1.1
Authorization: Basic Y29uZmk6ZGVudGlhbA==
User-Agent: InsaneBrowser
Host: www.myipv6.org
Accept: */*

5. Décodage du code : Y29uZmk6ZGVudGlhbA== (base 64) via le site https://www.base64decode.org/
6. Resulat du décryptage : confi:dential (mot de passe)

# V° BLUETOOTH - Fichier inconnu 
1. Démarrage du challenge
 2. Obtention du fichier ch18.bin
 3. Analyse du paquet dans Wireshark
 4. Clique : Wireless > Bluetooth Devices > illustration du contenue (Adresse MAC et nom du téléphone )
>  0c:b3:19:b9:4f:c6 SamsungE GT-S7390G
 5. Cryptage du code : 0C:B3:19:B9:4F:C6GT-S7390G via le site https://www.sha1.fr/
 6. Résultat : c1d0349c153ed96fe2fadf44e880aef9e69c122b (Mot de passe)
