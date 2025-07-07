default: $(MAKE)
make: bmrsa
nmake: bmrsa.exe

CPP=cl.exe
CPP_PROJ=/nologo /ML /Za /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" \
         /D "_MBCS" /FD /c 
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:console /incremental:no /pdb:"bmrsa.pdb" \
             /machine:I386 /out:"bmrsa.exe" 
CPP_SWITCHES=/nologo /ML /Za /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" \
             /D "_MBCS" /FD /c
	     
bmrsa.exe: bignum.obj bmrsa.obj Makefile 
	$(LINK32) $(LINK32_FLAGS) bignum.obj bmrsa.obj

bignum.obj: bignum.cpp bignum.h Makefile
	$(CPP) $(CPP_SWITCHES) bignum.cpp

bmrsa.obj: bmrsa.cpp bignum.h Makefile
	$(CPP) $(CPP_SWITCHES) bmrsa.cpp

winclean:
	-@erase bignum.obj
	-@erase bmrsa.obj
	-@erase *.idb
	-@erase bmrsa.exe
	-@erase testfile.txt
	-@erase encrypted.txt
	-@erase mykeys.txt

################## END MICROSOFT / BEGIN LINUX #################

CC = gcc
bmrsa.o: bmrsa.cpp bignum.h Makefile
	$(CC) -c bmrsa.cpp

bignum.o: bignum.cpp bignum.h Makefile
	$(CC) -c bignum.cpp

bmrsa: bmrsa.o bignum.o 
	$(CC) bmrsa.o bignum.o -o bmrsa -lm

clean:
	- /bin/rm *.o *~ \#* core mykeys.txt testfile.txt encrypted.txt
demo:
	- ./bmrsa -g 16 -f mykeys.txt
	- /bin/echo >testfile.txt This is a demonstration message
	- ./bmrsa -f mykeys.txt -pu -mit -mo6 <testfile.txt >encrypted.txt
	- ./bmrsa -f mykeys.txt -pr -mi6 -mot <encrypted.txt
