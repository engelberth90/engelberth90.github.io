---
layout: single
title: Configuración para auditorias mobiles PT 1.
date: 2023-11-01
classes: wide
header:
  #teaser: /assets/images/android-hacking.png
categories:
  - Mobile
tags:
  - Mobile
  - Windows
---
![](\assets\images\Hacking-mobile\android-hacking.png)

Dentro de este blog se llevara el paso a paso sobre lo que se necesita en un ambiente para las auditorias mobiles.

- [# Celular en modo Desarrollador](#celular-en-modo-Desarrollador)
- [# Descarga de platform tools para el uso de adb](#descarga-de-platform-tools-para-el-uso-de-adb)
- [# Instalación de frida](#instalación-de-frida)
- [# Instalación de certificado de Burp Suite](#instalación-de-certificado-de-burp-suite)
- [# Shellcode analysis #3: linux/x86/adduser](#shellcode-analysis-3-linuxx86adduser)
- [Stepping through the shellcode](#stepping-through-the-shellcode-2)

# celular en modo Desarrollador 
---------------------------------------

Para las auditorias mobiles se requiere de un celular rooteado, esta guia no abarca la manera de rootear un dispositivo mobile.

# Paso 1:
Acceder a las configuraciones del celular y dirigirnos a la opción `Acerca del telefono`.

![](\assets\images\Hacking-mobile\acerca-phone.jpeg)

# Paso 2:

Luego nos dirigimos a la opción de `Información del Software`, donde visualizaremos diferentes opciones pero nos centraremos en la opción de `Build number` para darle click varias veces hasta que nos diga que tenemos  activado el modo desarrollador.

![](\assets\images\Hacking-mobile\modo-desarrollador.jpeg)

# Paso 3:

Teniendo esto activo, nos dirigimos a las configuraciones generales y hasta abajo encontraremos la opción `Opcion de Desarrollador` o `Developer Options`.

![](\assets\images\Hacking-mobile\desarrollador-activo.jpeg)

# Paso 4:

Con esto hecho solo nos falta habilitar la depueración por ADB para que nos podamos conectar por medio de ADB al dispositivo.

![](\assets\images\Hacking-mobile\adb-on.jpeg)

# Descarga de Platform tools para el uso de ADB

# Paso 1:

Teniendo esto liso, procedemos a descargar el paquete de herramientas para SDK de android, en mi caso instalare el paquete para Windows:

![](\assets\images\Hacking-mobile\jdk-windows.png)

# Paso 2:

Para la siguiente ventana que se muestra solo tenemos que aceptar los terminos y se descargara el paquete para windows:

![](\assets\images\Hacking-mobile\jdk-download.png)

El sitio oficial para los paquetes JDK de android:
- [https://developer.android.com/tools/releases/platform-tools?hl=es-419](https://developer.android.com/tools/releases/platform-tools?hl=es-419)

# Paso 3:

Cuando se nos descargue el archivo `.zip` lo descomprimimos y se nos dara una carpeta donde contendra los archivos, pero el que mas estaremos usando es el `adb.exe`.

![](\assets\images\Hacking-mobile\adb-full.png)

luego abrimos una terminal dentro de la carpeta de platform-tools y con el comando `adb devices` listaremos los dispositivos android conectados a nuestro ordenador (el dispositivo android debe estar conectado por medio de un cable USB al ordenador).

![](\assets\images\Hacking-mobile\id-device.png)

Vemos que la respuesta es el valor del ID del dispositivo con el cual, procedemos a conectarnos con el comando `adb connect [ID-Device]`, luego de hacer la conección, con el comando `adb shell` obtenemos una shell interactica con el dispositivo Android

![](\assets\images\Hacking-mobile\abd-command.png)


# Instalación de frida

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

Para saber si nuestra arquitextura es de 32 o 64 bits, estas son sus clasificaciones:

32 Bits
-x86.
-armeabi-v7a.

64 Bits
-arm64-v8a.
-x86_64.

Luego necesitaremos descargar el binario que se adapte a la arquitectura de nuestro dispositivo, los binarios los podemos descargar del siguiente link:

- [https://github.com/frida/frida/releases](https://github.com/frida/frida/releases)

Luego de que identificamos el binario que necesitamos, damos click sobre el para descargarlo:

![](\assets\images\Hacking-mobile\descargando-serverfrida.png)

Veremos un archivo comprimido, procedemos a descomprimirlo para obtener el binario.
Luego de que tenemos el binario lo subiremos con el comando: `adb push [ruta del binario] [ruta a guardar celular]` 

![](\assets\images\Hacking-mobile\push-server.png)

luego ingresamos en la ruta /data/local/tmp dentro del celular para visualizar el binario y vemos que lo tenemos guardado, solo tenemos que darle permisos de ejecución con el siguiente comando : `chmod +x [file-name]`

![](\assets\images\Hacking-mobile\friida-server-command.png)

Teniendo listo el servidor de frida, procedemos a probar que exista conexion entre el server y el client de la siguiente manera, en adb ejecutamos frida server con el siguiente comando: `./frida-server-16.1.4-android-arm &` con `&` al final para mandarlo a segundo plano y asi poder hacer uso de la terminal de adb, luego desde frida client ejecutamos el siguiente comando: `frida-ps -U` el `frida-ps` es para especificar que queremos listar procesos del servidor de frida y el `-U` es para especificar que la conexion es por medio de USB.

![](\assets\images\Hacking-mobile\frida-ps.png)

Del lado de frida client, logramos ver los procesos que estan corriendo donde tenemos el servidor de frida.


