CC = i686-w64-mingw32-gcc
WINDRES = i686-w64-mingw32-windres
CFLAGS = --std=c99 -O2 -I contrib/$(WINDIVERT)/include/ -mwindows -mthreads \
    -mno-ms-bitfields -m32 -Wall -DVERSION=$(VERSION)
CLIBS = -lws2_32 -lkernel32 -L contrib/$(WINDIVERT)/x86/ -lWinDivert \
    -lcomctl32 -liphlpapi -mwindows
OBJS = main.o redirect.o domain.o allow.o
PROG = tallow.exe

$(PROG): $(OBJS)
	$(WINDRES) main.rc -O coff -o main.res
	$(CC) -s -o $(PROG) $(OBJS) main.res $(CLIBS)

clean:
	rm -rf $(OBJS) $(PROG)

