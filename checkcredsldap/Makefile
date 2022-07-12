BOFNAME := checkcredsldap
LIBINCLUDE := -l wldap32 -l netapi32 
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC=x86_64-w64-mingw32-clang

all:
	$(CC_x86) -Wall -o $(BOFNAME).x86.o -c ${BOFNAME}.c 
	$(CC_x64) -Wall -o $(BOFNAME).x64.o -c ${BOFNAME}.c 

clean:
	rm -f *.o
