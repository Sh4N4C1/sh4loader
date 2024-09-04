pub const MAKEFILE_: &str = r#"CCX64 := x86_64-w64-mingw32-gcc
SRC := src
INJECTION_SRC := src/method

# for threadless injection [remote/local normal/debug]

THREADLESS_INJECTION := -s -w -static -fpermissive -Wl,--subsystem,windows -nostdlib -Wl,--entry="Main" -Iinclude -Isrc/method -lkernel32 -masm=intel -DTHREADLESS_INJECTION -o ./payload.exe
THREADLESS_INJECTION_DEBUG := -s -w -static -fpermissive -Wl,--subsystem,console -nostdlib -Wl,--entry="Main" -Iinclude -Isrc/method -lkernel32 -luser32 -masm=intel -DTHREADLESS_INJECTION -DDEBUG -o ./payload.exe

# for msdtc.exe dll sideload [normal/debug]

MSDTC_DLL_SIDELOAD := -s -w -static -fpermissive -Wl,--subsystem,windows -nostdlib -Wl,--entry="DllMain" -Iinclude -shared -Isrc/method -lkernel32 -masm=intel -DMSDTC_DLL_SIDELOAD -o ./msdtctm.dll

MSDTC_DLL_SIDELOAD_DEBUG := -s -w -static -fpermissive -Wl,--subsystem,console -nostdlib -Wl,--entry="DllMain" -Iinclude -luser32 -shared -Isrc/method -lkernel32 -masm=intel -DMSDTC_DLL_SIDELOAD -DDEBUG -o ./msdtctm.dll


# for threadless injection [remote/local normal/debug]

threadless_injection_remote:
	nasm -f win64 ./src/asm/syscall.s -o ./src/asm/syscall.o
	nasm -f win64 ./src/asm/proxydll.s -o ./src/asm/proxydll.o
	nasm -f win64 ./src/asm/proxycall.s -o ./src/asm/proxycall.o
	@ $(CCX64) $(SRC)/*.c $(INJECTION_SRC)/threadless_injection.c $(SRC)/asm/*.o $(THREADLESS_INJECTION) -DREMOTE
threadless_injection_remote_debug:
	nasm -f win64 ./src/asm/syscall.s -o ./src/asm/syscall.o
	nasm -f win64 ./src/asm/proxydll.s -o ./src/asm/proxydll.o
	nasm -f win64 ./src/asm/proxycall.s -o ./src/asm/proxycall.o
	@ $(CCX64) $(SRC)/*.c $(INJECTION_SRC)/threadless_injection.c $(SRC)/asm/*.o $(THREADLESS_INJECTION_DEBUG) -DREMOTE
threadless_injection_local:
	nasm -f win64 ./src/asm/syscall.s -o ./src/asm/syscall.o
	nasm -f win64 ./src/asm/proxydll.s -o ./src/asm/proxydll.o
	nasm -f win64 ./src/asm/proxycall.s -o ./src/asm/proxycall.o
	@ $(CCX64) $(SRC)/*.c $(INJECTION_SRC)/threadless_injection.c $(SRC)/asm/*.o $(THREADLESS_INJECTION) -DLOCAL
threadless_injection_local_debug:
	nasm -f win64 ./src/asm/syscall.s -o ./src/asm/syscall.o
	nasm -f win64 ./src/asm/proxydll.s -o ./src/asm/proxydll.o
	nasm -f win64 ./src/asm/proxycall.s -o ./src/asm/proxycall.o
	@ $(CCX64) $(SRC)/*.c $(INJECTION_SRC)/threadless_injection.c $(SRC)/asm/*.o $(THREADLESS_INJECTION_DEBUG) -DLOCAL

# for msdtc dll sideload [normal/debug]

msdtc_dll_sideload:
	nasm -f win64 ./src/asm/syscall.s -o ./src/asm/syscall.o
	nasm -f win64 ./src/asm/proxydll.s -o ./src/asm/proxydll.o
	nasm -f win64 ./src/asm/proxycall.s -o ./src/asm/proxycall.o
	@ $(CCX64) $(SRC)/*.c ./linker.def $(INJECTION_SRC)/msdtc_dll_sideload.c $(SRC)/asm/*.o $(MSDTC_DLL_SIDELOAD)
msdtc_dll_sideload_debug:
	nasm -f win64 ./src/asm/syscall.s -o ./src/asm/syscall.o
	nasm -f win64 ./src/asm/proxydll.s -o ./src/asm/proxydll.o
	nasm -f win64 ./src/asm/proxycall.s -o ./src/asm/proxycall.o
	@ $(CCX64) $(SRC)/*.c ./linker.def $(INJECTION_SRC)/msdtc_dll_sideload.c $(SRC)/asm/*.o $(MSDTC_DLL_SIDELOAD_DEBUG)
clean:
	@ rm -rf $(DIST)/*

"#;
