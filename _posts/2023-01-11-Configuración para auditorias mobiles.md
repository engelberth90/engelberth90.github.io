---
layout: single
title: Configuración para auditorias mobiles.
date: 2023-11-03
classes: wide
header:
  #teaser: /assets/images/android-hacking.png
categories:
  - Mobile
tags:
  - Mobile
  - Frida
---
![](\assets\images\Hacking-mobile\android-hacking.png)

Dentro de este blog se llevara el paso a paso sobre lo que se necesita en un ambiente para las auditorias mobiles.

- [# Celular en modo Desarrollador](#celular-en-modo-Desarrollador)
- [# Descarga de platform tools para el uso de adb](#descarga-de-platform-tools-para-el-uso-de-adb)
- [# Instalacion de frida](#instalacion-de-frida)
- [# Instalacion de certificado de burp suite](#instalacion-de-certificado-de-burp-suite)

# celular en modo Desarrollador 
---------------------------------------

Para las auditorias mobiles se requiere de un celular rooteado, esta guia no abarca la manera de rootear un dispositivo.

# Paso 1:
Acceder a las configuraciones del celular y dirigirnos a la opción `Acerca del telefono`.

![](\assets\images\Hacking-mobile\acerca-phone.jpeg)

# Paso 2:

Nos dirigimos a la opción de `Software Information`, donde visualizaremos diferentes opciones pero nos centraremos en la opción de `Build number` para darle click varias veces hasta que nos diga que tenemos  activado el modo desarrollador.

![](\assets\images\Hacking-mobile\modo-desarrollador.jpeg)

# Paso 3:

Teniendo esto activo, nos dirigimos a las configuraciones generales y hasta abajo encontraremos `Opcion de Desarrollador` o `Developer Options`.

![](\assets\images\Hacking-mobile\desarrollador-activo.jpeg)

# Paso 4:

Habilitamos la depueración por ADB para que nos podamos conectar por medio de ADB al dispositivo.

![](\assets\images\Hacking-mobile\adb-on.jpeg)

# Descarga de Platform tools para el uso de ADB

# Paso 1:

Procedemos a descargar el paquete de herramientas para SDK de android, en mi caso instalare el paquete para Windows:

![](\assets\images\Hacking-mobile\jdk-windows.png)

# Paso 2:

Para la siguiente ventana que se muestra solo tenemos que aceptar los terminos y darle en descargar:

![](\assets\images\Hacking-mobile\jdk-download.png)

El sitio oficial para los paquetes JDK de android:
- [https://developer.android.com/tools/releases/platform-tools?hl=es-419](https://developer.android.com/tools/releases/platform-tools?hl=es-419)

# Paso 3:

Cuando se nos descargue el archivo `.zip` lo descomprimimos y nos dara una carpeta donde contendra los archivos, pero el que mas estaremos usando es el `adb.exe`.

![](\assets\images\Hacking-mobile\adb-full.png)

Ahora abrimos una terminal dentro de la carpeta de platform-tools y con el comando `adb devices` listaremos los dispositivos android conectados a nuestro ordenador (el dispositivo android debe estar conectado por medio de un cable USB al computador).

![](\assets\images\Hacking-mobile\id-device.png)

Vemos que la respuesta es el valor del ID del dispositivo con el cual procedemos a conectarnos con el comando `adb connect [ID-Device]`, luego de hacer la conección, con el comando `adb shell` obtenemos una shell interactica con el dispositivo Android

![](\assets\images\Hacking-mobile\abd-command.png)


# Instalacion de frida

# Paso 1:

Primero se necesita instalar python en nuestro ordenador y agregar python al path del systema.
- [https://www.python.org/downloads/](https://www.python.org/downloads/)

# Paso 2:

Para instalar frida cliente, solo necesitamos ejecutar el siguiente comando en la terminal de windowss: `pip install frida-tools`

![](\assets\images\Hacking-mobile\instalando-frida.png)

Como logramos ver, instalamos la herramienta de frida y lo comprobamos lanzando el comando `frida --version` la cual nos muestra la versión de frida que tenemos instalada.

# Paso 3:

Para frida server, primero necesitamos saber la arquitectura del dispositivo android, eso lo podemos hacer conectandonos por ADB y ejecutando el siguiente comando:`getprop ro.product.cpu.abi`

![](\assets\images\Hacking-mobile\arquitectura-phone.png)

Para saber si nuestra arquitectura es de 32 o 64 bits, estas son sus clasificaciones:

32 Bits
- x86.
- armeabi-v7a.


64 Bits
- arm64-v8a.
- -x86_64.


Luego necesitaremos descargar el binario que se adapte a la arquitectura de nuestro dispositivo, los binarios los podemos descargar del siguiente link:

- [https://github.com/frida/frida/releases](https://github.com/frida/frida/releases)

Luego de que identificamos el binario que necesitamos, damos click sobre el para descargarlo:

![](\assets\images\Hacking-mobile\descargando-serverfrida.png)

Veremos un archivo comprimido, procedemos a descomprimirlo para obtener el binario.
Luego de que tenemos el binario lo subiremos con el comando: `adb push [ruta del binario] [ruta a guardar en el celular]` 

![](\assets\images\Hacking-mobile\push-server-ofuscado.png)

luego ingresamos en la ruta /data/local/tmp dentro del celular para visualizar el binario y vemos que lo tenemos guardado, solo tenemos que darle permisos de ejecución con el siguiente comando : `chmod +x [file-name]`

![](\assets\images\Hacking-mobile\friida-server-command.png)

Teniendo listo el servidor de frida, procedemos a probar que exista conexion entre el server y el client de la siguiente manera, en adb ejecutamos frida server con el siguiente comando: `./frida-server-16.1.4-android-arm &` con `&` al final para mandarlo a segundo plano y asi poder hacer uso de la terminal de adb, luego desde frida client ejecutamos el siguiente comando: `frida-ps -U` el `frida-ps` es para especificar que queremos listar procesos del servidor de frida y el `-U` es para especificar que la conexion es por medio de USB.

![](\assets\images\Hacking-mobile\frida-ps.png)

Del lado de frida client, logramos ver los procesos que estan corriendo donde tenemos el servidor de frida.

#  Instalacion de certificado de burp suite

# Paso 1:

Abrimos nuestro burp suite y nos dirigimos a la opcion de proxy -> proxy settings:

![](\assets\images\Hacking-mobile\proxy-settings.png)
 
 Dentro de `Proxy Settings` encontraremos la opción de `Regenerate CA certificate`:

![](\assets\images\Hacking-mobile\regenerate-certificate.png)


 Le damos click y aceptamos la advertencia de regenerar un nuevo certificado.
 Luego de esto en la configuracion de proxy, establecemos la IP que nos da nuestro router con un puerto:

![](\assets\images\Hacking-mobile\IP-Port.png)

Hecho esto, nos dirigimos a las configuraciones de nuestro celular de pruebas, vamos a `WIFI` y damos click en el WIFI al que estamos conectados (es necesario que el celular y la computadora esten conectado en la misma red), ahora buscamos la opcion de `Proxy` donde especificaremos la IP y puerto que configuramos en burp suite:

![](\assets\images\Hacking-mobile\configurando-proxy.png)

 Con esto hecho, nos dirigimos a Google Chrome y en el buscador colocamos la direccion IP y Puerto de burpsuite para descargar el certificado desde el servidor web:

![](\assets\images\Hacking-mobile\descargando-certificado.png)

Ahora buscamos nuestro certificado y veremos que tiene una extension `.der` que tendremos que cambiar a `.cer`

Volvemos a configuraciones del celular y buscamos la opcion de Encriptacion de credenciales:

![](\assets\images\Hacking-mobile\credenciales.png)

Entramos a esta opcion y nos dirigimos a `Instalar desde la tarjeta SD`, ahora tenemos que buscar el certificado que descargamos, cuando lo seleccionemos les pedira autenticarse para confirmar la instalacion del certificado, despues de esto les pedire que le den un nombre al certificado, en este caso le dare el nombre de `Burp`

![](\assets\images\Hacking-mobile\name-certificate.png)

Tienen que instalar el certificado para las opciones que les permita como: `VPN, WIFI, Apps`.

Ahora el certificado les aparecera instalado en el apartado de Usuario.

![](\assets\images\Hacking-mobile\certificado-user.png)

Pero para poder interceptar necesitaremos el certificado a nivel de `sistema` y no de `usuario`, entonces para esto haremos uso de `Magisk` la cual es una herramienta que nos permite instalar modulos dependiendo de nuestras necesidades:

![](\assets\images\Hacking-mobile\magisk.png)

En nuetro caso el modulo `Always Trust User Certificates` nos ayuda a pasar el certificado a nivel de usuario a un certificado a nivel de sistema, esto lo logramos haciendo un reinicio del celular.

Despues de reiniciar el dispositivo, vamos a ver las credenciales a nivel de sistema y encontramos el certificado de `PortSwigger`.

![](\assets\images\Hacking-mobile\system-certificate.png)

Ahora para asegurarnos de que podemos interceptar las peticiones web que salgan desde el celular con Burp Suite, nos dirigimos a `Pxory > HTTP History` dentro de Burp Suite y en el celular vamos a Google Chrome e ingresamos a cualquier pagina solo para assegurarnos que interceptamos las peticiones burp suite:

![](\assets\images\Hacking-mobile\interceptando.png)

Vemos que todo esta funcionando de maravilla ya que logramos interceptar las peticiones.

Espero este post sea de utilidad para las personas que quieren empezar en el mundo de la ciberseguridad.

HAPPY HACKING!