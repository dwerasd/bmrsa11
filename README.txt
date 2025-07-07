Written by Benjamin Marty (BlueMonkMN@email.com)
Copyleft 2003 - distributed under GPL
   http://www.fsf.org/copyleft/
http://bmrsa.sf.net/
This program is an exercise in prime number generation,
RSA key generation, RSA encryption and conversion between
decimal, hexadecimal, base64 and text.  Take note that RSA
is generally not used to encrypt entire messages because it
is too slow.  It is normally used to encrypt keys used in
other encryption algorithms or other relatively small
values.  For more detailed documentation, execute bmrsa
from a command line without passing any arguments.  You will
probably want to pipe the output through more like this
> bmrsa | more

===================== GNU / LINUX ==========================
NOTE: I UPDATED BMRSA SOURCE CODE, BUT DO NOT HAVE a LINUX
SYSTEM HANDY SO THE LINUX BMRSA BINARY INCLUDED IN THE
ARCHIVE IS OUT OF DATE.
To build bmrsa:
-------------------- Command Line --------------------------
# make
------------------- Sample Results -------------------------
gcc -c bmrsa.cpp
gcc -c bignum.cpp
gcc bmrsa.o bignum.o -o bmrsa -lm
------------------- End of Results -------------------------

To see a demo
-------------------- Command Line --------------------------
# make demo
------------------- Sample Results -------------------------
./bmrsa -g 16 -f mykeys.txt
Generating random number:
5A180808D022A3FCB51EB50F64DA2A72
Testing for prime:
119755297702764153679979413525052926579
It's evenly divisible by 41
Testing for prime:
[... lots of details ...]
No small prime factors; trying Lehman method
Lehman result 0 suggests prime (1)
Lehman result 1 suggests prime (1)
Lehman result 2 suggests prime (1)
Lehman result 3 suggests prime (1)
Lehman result 4 suggests prime (1)
Lehman result 5 suggests prime (1)
Lehman result 6 suggests prime (1)
10753822105049858116160862132450630463
Appears prime
Tested 22 numbers before finding a prime. Resorted to Lehman method 3 times.
Process took   19.0 seconds.
Generating random number:
D62C95085E841CB856B4AD6D5A33906E
/bin/echo >testfile.txt This is a demonstration message
./bmrsa -f mykeys.txt -pu -mit -mo6 <testfile.txt >encrypted.txt
./bmrsa -f mykeys.txt -pr -mi6 -mot <encrypted.txt
This is a demonstration message
------------------- End of Results -------------------------

=============== WINDOWS / VISUAL STUDIO 6/7 ================
To build bmrsa (first run vcvars32.bat to set up command
line environment for VC6.0, or open a .NET command prompt):
-------------------- Command Line --------------------------
>nmake
------------------- Sample Results -------------------------
Microsoft (R) Program Maintenance Utility Version 7.00.9466
Copyright (C) Microsoft Corporation.  All rights reserved.

        cl.exe /nologo /ML /Za /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"
 /D "_MBCS" /FD /c bignum.cpp
bignum.cpp
        cl.exe /nologo /ML /Za /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"
 /D "_MBCS" /FD /c bmrsa.cpp
bmrsa.cpp
        link.exe /nologo /subsystem:console /incremental:no /pdb:"bmrsa.pdb"  /m
achine:I386 /out:"bmrsa.exe" bignum.obj bmrsa.obj
----------------- End of Results -------------------------

To see a demo
-------------------- Command Line --------------------------
>demo.bat
--------------(results are similar to Linux)----------------
