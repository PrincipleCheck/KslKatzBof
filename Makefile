CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Os -masm=intel -Wall -Wno-unused-variable -Wno-unused-function \
          -Wno-incompatible-pointer-types \
          -fno-stack-protector -fno-builtin \
          -I src
OUTDIR  = bin

.PHONY: all clean

all: $(OUTDIR)/kslkatzbof.x64.o

$(OUTDIR)/kslkatzbof.x64.o: src/main.c
	@mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -c src/main.c -o $@
	@echo "[+] Built $@"

clean:
	rm -f $(OUTDIR)/kslkatzbof.x64.o
