Benchmarks
==========

This folder contains simple micro-benchmarks to measure encryption and in-memory PE load performance.

crypt_bench.c
- Measures XOR vs AES-GCM encryption time over multiple iterations for a provided file.

pe_load_bench.c
- Measures the time to allocate and copy headers/sections for an EXE/DLL into a memory image repeatedly.

Build (MSYS2 / MinGW-w64)
-------------------------
From an MSYS2 MinGW64 shell with OpenSSL installed:

```powershell
x86_64-w64-mingw32-gcc -O2 -march=native -o crypt_bench.exe crypt_bench.c -lcrypto -lssl
x86_64-w64-mingw32-gcc -O2 -march=native -o pe_load_bench.exe pe_load_bench.c
```

Run examples
------------
```powershell
./crypt_bench.exe ..\tests\message_c.exe 20
./pe_load_bench.exe ..\tests\message_c.exe 500
```

Safety
------
- These benchmarks only load and copy data; they do not execute payload entrypoints.
- Still test inside an isolated environment when using unknown binaries.
