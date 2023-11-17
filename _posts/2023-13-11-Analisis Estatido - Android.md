---
layout: single
title: Analisis estatico - Android
date: 2023-11-13
classes: wide
header:
  #teaser: /assets/images/Estatico-Android/rootME.jpg
categories:
  - Static Analysis
  - Android Hacking
  - Mobile
tags:
  - Analysis
  - MobSF
  - JADX
  - APK Tool  
---

## Static analysis of android applications

![](/assets/images/Estatico-Android/android-phone-root.jpg)

Esta publicación cubrira la primer parte de las auditorias mobiles, la cual es el analisis dinamico de una sobre un APK.

### Resumen

- Extraer APK del dispotivo.
- Analisis estatico automatico con MOBSF.
- Analisis estatico manual con JADX.
- Apktool.

### Tools used

- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [JADX](https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-gui-1.4.7-no-jre-win.exe)
- [Apktool](https://github.com/iBotPeaches/Apktool)

### Extraer el APK desde un dispositivo fisico

Tenemos que conectarnos por ADB al dispositivo para luego ejecutar el siguiente comando: `pm list packages -3 | grep injured`, en la primer seride de comandos lo que hacermos es decirle al sistema que nos liste todos los paquetes de terceros, ya  con la ayuda del `|` y del comando `grep` le pedimos que busque una palabra clave la cual es `injured`, la palabara la buscamos basandonos en el nobre de la aplicación y asi no ver todos los paquetes de terceros que existen en el dispositivo.

Con esto ahora usamos de nuevo el comando `pm` para encontrar la ruta completa del apk especificando el paquete con el siguiente comando: `pm path [package]`:

![](/assets/images/Estatico-Android/ruta-apk.png)

Con la ruta completa del apk, ahora solo tendremos que salirnos de adb para luego sacar el apk con el siguiente comando de abd: `adb pull [ruta-apk] [ruta-destino-windows]`:

![](/assets/images/Estatico-Android/base-apk.png)


### MobSF

Nos dirigimos a nuestra maquina Linux, en mi caso sera `Kali Linux` y necesitaremos clonar el repositorio de MobSF con el siguiente comando `git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git`.

```
┌──(T1N0㉿kali)-[~/Documents/mobile]
└─$ git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
Cloning into 'Mobile-Security-Framework-MobSF'...
remote: Enumerating objects: 19583, done.
remote: Counting objects: 100% (56/56), done.
remote: Compressing objects: 100% (49/49), done.
remote: Total 19583 (delta 15), reused 32 (delta 7), pack-reused 19527
Receiving objects: 100% (19583/19583), 1.28 GiB | 5.09 MiB/s, done.
Resolving deltas: 100% (9946/9946), done.
Updating files: 100% (414/414), done.
                                       
┌──(T1N0㉿kali)-[~/Documents/mobile]
└─$

```

Luego de clonar el repositorio, necesitaremos montar un contenedor de docker con la herramienta para hacer uso de todos los recursos que MobSF necesita, utilizaremos el comando: `docker pull opensecurity/mobile-security-framework-mobsf:latest`, para este punto tendremos que tenes instalado docker en nuestra maquina linux:

```                                                           
┌──(T1N0㉿kali)-[~/Documents/mobile]
└─$ ls
Mobile-Security-Framework-MobSF-master  frida-ios-dump
                                   
┌──(T1N0㉿kali)-[~/Documents/mobile]
└─$ docker pull opensecurity/mobile-security-framework-mobsf:latest
Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg.
Resolving "opensecurity/mobile-security-framework-mobsf" using unqualified-search registries (/etc/containers/registries.conf)
Trying to pull docker.io/opensecurity/mobile-security-framework-mobsf:latest...
Getting image source signatures
Copying blob 8139a2a49df9 done   | 
Copying blob aece8493d397 done   | 
Copying blob 8bbacf946a3d done   | 
Copying blob 02f63342b317 done   | 
Copying blob e7e46b9b5179 done   | 
Copying blob 30cbb6552ee4 done   | 
Copying blob f27b16f93b73 done   | 
Copying blob 316681fcd87d done   | 
Copying blob b83925685b53 done   | 
Copying blob 10a0d6b4850a done   | 
Copying blob f263346286ea done   | 
Copying blob 4f4fb700ef54 done   | 
Copying blob 326e7ea8ab66 done   | 
Copying config 6fb1f6bb37 done   | 
Writing manifest to image destination
6fb1f6bb372c092093dfd17f8ad0d5862879e8c60459083c3688b9a73f20519e
                                    
┌──(T1N0㉿kali)-[~/Documents/mobile]
└─$ 
```
Seguido esto ya solo necesitamos correr el contenedor en nuestro local host y especificando en el puerto local `8080` con el siguiente comando: `docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf`.

```
┌──(T1N0㉿kali)-[~/Documents/mobile]
└─$ docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg.
[INFO] 14/Nov/2023 06:38:38 - 
  __  __       _    ____  _____       _____ _____   
 |  \/  | ___ | |__/ ___||  ___|_   _|___ /|___  |
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / |_ \   / / 
 | |  | | (_) | |_) |__) |  _|  \ V / ___) | / /  
 |_|  |_|\___/|_.__/____/|_|     \_/ |____(_)_/ 

[INFO] 14/Nov/2023 06:38:38 - Mobile Security Framework v3.7.9 Beta
REST API Key: cefaeead14956b4d4e7ef92d24317cb70670730fab1dc30971c6d0357c65cbe0
[INFO] 14/Nov/2023 06:38:38 - OS: Linux
[INFO] 14/Nov/2023 06:38:38 - Platform: Linux-6.5.0-kali3-amd64-x86_64-with-glibc2.35
[INFO] 14/Nov/2023 06:38:38 - Dist: ubuntu 22.04 Jammy Jellyfish
[INFO] 14/Nov/2023 06:38:38 - MobSF Basic Environment Check
No changes detected
[INFO] 14/Nov/2023 06:38:38 - Checking for Update.
[INFO] 14/Nov/2023 06:38:39 - No updates available.
[INFO] 14/Nov/2023 06:38:41 - 
  __  __       _    ____  _____       _____ _____   
 |  \/  | ___ | |__/ ___||  ___|_   _|___ /|___  |
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / |_ \   / / 
 | |  | | (_) | |_) |__) |  _|  \ V / ___) | / /  
 |_|  |_|\___/|_.__/____/|_|     \_/ |____(_)_/   

[INFO] 14/Nov/2023 06:38:41 - Mobile Security Framework v3.7.9 Beta
REST API Key: cefaeead14956b4d4e7ef92d24317cb70670730fab1dc30971c6d0357c65cbe0
[INFO] 14/Nov/2023 06:38:41 - OS: Linux
[INFO] 14/Nov/2023 06:38:41 - Platform: Linux-6.5.0-kali3-amd64-x86_64-with-glibc2.35
[INFO] 14/Nov/2023 06:38:41 - Dist: ubuntu 22.04 Jammy Jellyfish
[INFO] 14/Nov/2023 06:38:41 - MobSF Basic Environment Check
Migrations for 'StaticAnalyzer':
  mobsf/StaticAnalyzer/migrations/0001_initial.py
    - Create model RecentScansDB
    - Create model StaticAnalyzerAndroid
    - Create model StaticAnalyzerIOS
    - Create model StaticAnalyzerWindows
    - Create model SuppressFindings
[INFO] 14/Nov/2023 06:38:42 - Checking for Update.
[INFO] 14/Nov/2023 06:38:42 - No updates available.
[INFO] 14/Nov/2023 06:38:46 - 
  __  __       _    ____  _____       _____ _____   
 |  \/  | ___ | |__/ ___||  ___|_   _|___ /|___  |
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / |_ \   / / 
 | |  | | (_) | |_) |__) |  _|  \ V / ___) | / /  
 |_|  |_|\___/|_.__/____/|_|     \_/ |____(_)_/  
                                                    
[INFO] 14/Nov/2023 06:38:46 - Mobile Security Framework v3.7.9 Beta
REST API Key: cefaeead14956b4d4e7ef92d24317cb70670730fab1dc30971c6d0357c65cbe0
[INFO] 14/Nov/2023 06:38:46 - OS: Linux
[INFO] 14/Nov/2023 06:38:46 - Platform: Linux-6.5.0-kali3-amd64-x86_64-with-glibc2.35
[INFO] 14/Nov/2023 06:38:46 - Dist: ubuntu 22.04 Jammy Jellyfish
[INFO] 14/Nov/2023 06:38:46 - MobSF Basic Environment Check
Operations to perform:
  Apply all migrations: StaticAnalyzer, auth, contenttypes, sessions
Running migrations:
  Applying StaticAnalyzer.0001_initial... OK
  Applying contenttypes.0001_initial... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0001_initial... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying auth.0007_alter_validators_add_error_messages... OK
  Applying auth.0008_alter_user_username_max_length... OK
  Applying auth.0009_alter_user_last_name_max_length... OK
  Applying auth.0010_alter_group_name_max_length... OK
  Applying auth.0011_update_proxy_permissions...[INFO] 14/Nov/2023 06:38:46 - Checking for Update.
 OK
  Applying auth.0012_alter_user_first_name_max_length... OK
  Applying sessions.0001_initial... OK
[INFO] 14/Nov/2023 06:38:47 - No updates available.
[INFO] 14/Nov/2023 06:38:50 - 
  __  __       _    ____  _____       _____ _____   
 |  \/  | ___ | |__/ ___||  ___|_   _|___ /|___  |
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / |_ \   / / 
 | |  | | (_) | |_) |__) |  _|  \ V / ___) | / /  
 |_|  |_|\___/|_.__/____/|_|     \_/ |____(_)_/  
                                                  
[INFO] 14/Nov/2023 06:38:50 - Mobile Security Framework v3.7.9 Beta
REST API Key: cefaeead14956b4d4e7ef92d24317cb70670730fab1dc30971c6d0357c65cbe0
[INFO] 14/Nov/2023 06:38:50 - OS: Linux
[INFO] 14/Nov/2023 06:38:50 - Platform: Linux-6.5.0-kali3-amd64-x86_64-with-glibc2.35
[INFO] 14/Nov/2023 06:38:50 - Dist: ubuntu 22.04 Jammy Jellyfish
[INFO] 14/Nov/2023 06:38:50 - MobSF Basic Environment Check
Operations to perform:
  Synchronize unmigrated apps: DynamicAnalyzer, MalwareAnalyzer, MobSF, messages, staticfiles
  Apply all migrations: StaticAnalyzer, auth, contenttypes, sessions
Synchronizing apps without migrations:
  Creating tables...
    Running deferred SQL...
Running migrations:
  No migrations to apply.
[INFO] 14/Nov/2023 06:38:50 - Checking for Update.
[INFO] 14/Nov/2023 06:38:50 - No updates available.
[INFO] 14/Nov/2023 06:38:53 - 
  __  __       _    ____  _____       _____ _____   
 |  \/  | ___ | |__/ ___||  ___|_   _|___ /|___  |
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / |_ \   / / 
 | |  | | (_) | |_) |__) |  _|  \ V / ___) | / /  
 |_|  |_|\___/|_.__/____/|_|     \_/ |____(_)_/ 
                                                 
[INFO] 14/Nov/2023 06:38:53 - Mobile Security Framework v3.7.9 Beta
REST API Key: cefaeead14956b4d4e7ef92d24317cb70670730fab1dc30971c6d0357c65cbe0
[INFO] 14/Nov/2023 06:38:53 - OS: Linux
[INFO] 14/Nov/2023 06:38:53 - Platform: Linux-6.5.0-kali3-amd64-x86_64-with-glibc2.35
[INFO] 14/Nov/2023 06:38:53 - Dist: ubuntu 22.04 Jammy Jellyfish
[INFO] 14/Nov/2023 06:38:53 - MobSF Basic Environment Check
No changes detected
[INFO] 14/Nov/2023 06:38:53 - Checking for Update.
[INFO] 14/Nov/2023 06:38:54 - No updates available.
[INFO] 14/Nov/2023 06:38:57 - 
  __  __       _    ____  _____       _____ _____   
 |  \/  | ___ | |__/ ___||  ___|_   _|___ /|___  |
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / |_ \   / / 
 | |  | | (_) | |_) |__) |  _|  \ V / ___) | / /  
 |_|  |_|\___/|_.__/____/|_|     \_/ |____(_)_/  
                                                 
[INFO] 14/Nov/2023 06:38:57 - Mobile Security Framework v3.7.9 Beta
REST API Key: cefaeead14956b4d4e7ef92d24317cb70670730fab1dc30971c6d0357c65cbe0
[INFO] 14/Nov/2023 06:38:57 - OS: Linux
[INFO] 14/Nov/2023 06:38:57 - Platform: Linux-6.5.0-kali3-amd64-x86_64-with-glibc2.35
[INFO] 14/Nov/2023 06:38:57 - Dist: ubuntu 22.04 Jammy Jellyfish
[INFO] 14/Nov/2023 06:38:57 - MobSF Basic Environment Check
No changes detected in app 'StaticAnalyzer'
[INFO] 14/Nov/2023 06:38:57 - Checking for Update.
[INFO] 14/Nov/2023 06:38:57 - No updates available.
[INFO] 14/Nov/2023 06:39:00 - 
  __  __       _    ____  _____       _____ _____   
 |  \/  | ___ | |__/ ___||  ___|_   _|___ /|___  |
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / |_ \   / / 
 | |  | | (_) | |_) |__) |  _|  \ V / ___) | / /  
 |_|  |_|\___/|_.__/____/|_|     \_/ |____(_)_/   
                                                    
[INFO] 14/Nov/2023 06:39:00 - Mobile Security Framework v3.7.9 Beta
REST API Key: cefaeead14956b4d4e7ef92d24317cb70670730fab1dc30971c6d0357c65cbe0
[INFO] 14/Nov/2023 06:39:00 - OS: Linux
[INFO] 14/Nov/2023 06:39:00 - Platform: Linux-6.5.0-kali3-amd64-x86_64-with-glibc2.35
[INFO] 14/Nov/2023 06:39:00 - Dist: ubuntu 22.04 Jammy Jellyfish
[INFO] 14/Nov/2023 06:39:00 - MobSF Basic Environment Check
Operations to perform:
  Apply all migrations: StaticAnalyzer, auth, contenttypes, sessions
Running migrations:
  No migrations to apply.
[INFO] 14/Nov/2023 06:39:01 - Checking for Update.
[INFO] 14/Nov/2023 06:39:01 - No updates available.
[2023-11-14 06:39:01 +0000] [1] [INFO] Starting gunicorn 21.2.0
[2023-11-14 06:39:01 +0000] [1] [INFO] Listening at: http://0.0.0.0:8000 (1)
[2023-11-14 06:39:01 +0000] [1] [INFO] Using worker: gthread
[2023-11-14 06:39:01 +0000] [56] [INFO] Booting worker with pid: 56

```
 Solo necesitamos especificar `http://0.0.0.0:8000` en nuestro navegador de kali linux para poder acceder a la herramienta de MobSF.

![](/assets/images/Estatico-Android/mobsf.png)

Para poder empezar analizar un APK, solo necesitamos dar click a la opción de `Upload & Analyze` y seleccionar nuesta APK:

![](/assets/images/Estatico-Android/uploading-apk.png)

Luego de que se cargue y analice el APK podremos empezar a ver los resultados sobre el analisis:

![](/assets/images/Estatico-Android/resultado-mobsf.png)

Con los resultados de MobSF podremos encontrar algunos correos que aveces son de utilidad para las auditorias ya que, en algunos casos, encontramos correos corporativos dentro del codigo de la aplicación:

![](/assets/images/Estatico-Android/email-mobsf.png)

De la misma manera MobSF nos mostrara palabras hardcodeadas dentro de la aplicación que algunas veces podran ser de utilidad:

![](/assets/images/Estatico-Android/hardocode-mobsf.png)

Ahora solo tendremos que interpretar los resultados que nos entrega MobSF para encontrar fallas de seguridad.

### JADX

JADX es una herramienta que nos ayuda a descompilar de `.DEX` a `java`, la herramienta la podemos usar de manera grafica o desde linea de comandos, para esta explicación se utilizara la version grafica en windows.

Luego de instalar JADX procedemos abrir la herramienta y veremos algo como esto:

![](/assets/images/Estatico-Android/open-jadx.png)

Donde solo tendremos que dar click en la opcion `Open file` donde nosotros tendremos que buscar el apk el cual analizaremos y luego de que cargue y JADX haga su trabajo veremos algo como esto:

![](/assets/images/Estatico-Android/open-jadx.png)

JADX nos ofrece una funcionalidad que en lo personal creo que es de las mejores y la cual es poder hacer una busqueda de palabras clave en todo el paquete:

![](/assets/images/Estatico-Android/fidn-jadx.png)

Esta es una pequeña lista que siempre utilizo en mis auditorias:

- user
- username
- pass 
- password
- key
- token
- http://
- https://
- secret
- databaseschema
- @gmail
- md5
- base64
- database
- github
- firebase
- aws
- cloud
- domain
- dns
- host
- ip
- port
- uri
- url
- conecction
- mysql
- ftp
- target

![](/assets/images/Estatico-Android/resultados-jadx.png)

Sabiendo esto y viendo los resultados para cada palabra clave que ingresemos solo necesitamos indagar mas entre el codigo fuente para encontrar algo que nos sea de utilidad a la hora de una auditoria