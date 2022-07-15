BOFNAME := checkcredsldap
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC=x86_64-w64-mingw32-clang
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip

all:
	$(CC_x86) -Wall -o $(BOFNAME).x86.o -c ${BOFNAME}.c 
	$(CC_x64) -Wall -o $(BOFNAME).x64.o -c ${BOFNAME}.c 
	$(STRIP_x64) --strip-unneeded $(BOFNAME).x64.o 
	$(STRIP_x86) --strip-unneeded $(BOFNAME).x86.o 

clean:
	rm -f *.o
