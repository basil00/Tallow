CC = x86_64-w64-mingw32-gcc
CFLAGS = --std=c99 -I contrib/WinDivert-1.0.5-MINGW/include/
CLIBS = -lws2_32 -lkernel32 -L contrib/WinDivert-1.0.5-MINGW/amd64/ -l WinDivert
OBJS = tor_wall.o

tor_wall: $(OBJS)
	$(CC) -s -o tor_wall.exe $(OBJS) $(CLIBS)

clean:
	rm -rf $(OBJS) tor_wall.exe

