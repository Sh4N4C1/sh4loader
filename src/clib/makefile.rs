pub const MAKEFILE: &str = r#"
CC = x86_64-w64-mingw32-gcc 
SRC_DIR = src
SRCS = $(wildcard $(SRC_DIR)/*.c)
EXECUTABLE = run.exe
OPTIONS := -masm=intel -lwininet -Iinclude

all: $(EXECUTABLE)
$(EXECUTABLE): 
	nasm -f win64 ./bin/IndirectSyscall.asm -o ./bin/IndirectSyscall.o
	$(CC) -DDEBUG $(SRCS) ./bin/IndirectSyscall.o $(CFLAGS) $(OPTIONS) -o $@


localcommoninj: 
	nasm -f win64 ./bin/IndirectSyscall.asm -o ./bin/IndirectSyscall.o
	x86_64-w64-mingw32-gcc -s -w -fpermissive -static -lpsapi  src/web.c src/indirectsyscall.c src/LocalCommonInj.c src/main.c src/tool.c ./src/cJSON.c ./src/Anti.c ./bin/IndirectSyscall.o -masm=intel -lwininet -Iinclude -o LocalCommonInj 

SpoofstacksLocalInj: 
	nasm -f win64 ./bin/IndirectSyscall.asm -o ./bin/IndirectSyscall.o
	nasm -f win64 ./bin/ProxyHelper.asm -o ./bin/ProxyHelper.o
	x86_64-w64-mingw32-gcc -s -w -fpermissive -static -lpsapi src/web.c src/indirectsyscall.c src/SpoofstacksLocalInj.c src/main.c  src/tool.c ./src/cJSON.c ./src/Anti.c ./bin/IndirectSyscall.o ./bin/ProxyHelper.o  -masm=intel -lwininet -Iinclude -o SpoofstacksLocalInj

CarokannSpoofstacksLocalInj: 
	nasm -f win64 ./bin/IndirectSyscall.asm -o ./bin/IndirectSyscall.o
	nasm -f win64 ./bin/ProxyHelper.asm -o ./bin/ProxyHelper.o
	x86_64-w64-mingw32-gcc -s -w -fpermissive -static -lpsapi  src/web.c src/indirectsyscall.c src/CarokannSpoofstacksLocalInj.c src/main.c ./src/cJSON.c src/tool.c ./src/Anti.c ./bin/IndirectSyscall.o ./bin/ProxyHelper.o  -masm=intel -lwininet -Iinclude -o CarokannSpoofstacksLocalInj

KannThreadlessCommonInj:
	nasm -f win64 ./bin/IndirectSyscall.asm -o ./bin/IndirectSyscall.o
	nasm -f win64 ./bin/ProxyHelper.asm -o ./bin/ProxyHelper.o
	x86_64-w64-mingw32-gcc -s -w -fpermissive -static -lpsapi src/web.c src/indirectsyscall.c src/KannThreadlessCommonInj.c src/main.c src/tool.c src/process.c ./src/cJSON.c ./src/Anti.c ./bin/IndirectSyscall.o ./bin/ProxyHelper.o -masm=intel -Wl,--subsystem,windows -lwininet -Iinclude -o KannThreadlessCommonInj

KannThreadlessStackInj:
	nasm -f win64 ./bin/IndirectSyscall.asm -o ./bin/IndirectSyscall.o
	nasm -f win64 ./bin/ProxyHelper.asm -o ./bin/ProxyHelper.o
	x86_64-w64-mingw32-gcc  -s -w -fpermissive -static -lpsapi src/indirectsyscall.c  src/main.c src/tool.c ./bin/IndirectSyscall.o ./bin/ProxyHelper.o ./src/web.c ./src/Anti.c ./src/cJSON.c ./src/KannThreadStackInj.c ./src/process.c -masm=intel -Wl,--subsystem,windows -lwininet -Iinclude -o KannThreadlessStackInj
"#;
