#!/usr/bin/env python

# -*- coding utf-8 -*-



import os



def figlet():

	os.system ("apt-get install figlet")

	os.system ("apt-get install lolcat")

	os.system ("apt-get install nmap")

	os.system ("apt-get install gobuster")

	os.system ("apt-get install hydra")

	os.system ("apt-get install binwalk")

	os.system ("apt-get install macchanger")

	os.system ("apt-get install hashcat")

	os.system ("apt-get install wafw00f")

	os.system ("apt-get install ike-scan")

	os.system ("apt-get install openvpn")

	os.system ("apt-get install exiftool")

	os.system ("apt-get install crunch")

	os.system ("apt-get install fcrackzip")

	os.system ("apt-get install john")

	os.system ("apt install weevely")

	os.system ("apt install searchsploit")

	os.system ("clear")

	ilk=os.popen("pwd").read()

	os.chdir("../../../../../../../")

	os.chdir("usr/share/wordlists")

	os.system("cp -r * "+ilk+"/src/wordlists")

	os.system ("figlet MIRLEX-TOOLKIT")

	print("""

	-------------------------------------------------

	|Now you are ready, you can start Mirlex-TOOLKIT|

	-------------------------------------------------

	""")

figlet()

