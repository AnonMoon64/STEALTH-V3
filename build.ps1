# PowerShell build script for STEALTH
# - Checks for MinGW (x86_64-w64-mingw32-gcc) and provides MSVC alternative instructions.
# - Builds: stealth_cryptor.exe, binder.exe, stub.exe, template.dll, hook.dll

param(
    [switch]$msvc
)

function Check-Program($name) {
    $p = Get-Command $name -ErrorAction SilentlyContinue
    return $p -ne $null
}

Write-Host "=== STEALTH build helper ==="
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $root

if ($msvc) {
    Write-Host "MSVC selected. Use Developer Command Prompt or Visual Studio tools. Sample commands:" -ForegroundColor Yellow
    Write-Host "cl /nologo /EHsc /MD stealth_cryptor.c /Fe:stealth_cryptor.exe"
    Write-Host "cl /nologo /EHsc /MD binder.c /Fe:binder.exe"
    Write-Host "cl /nologo /EHsc /MD stub.c /Fe:stub.exe"
    Write-Host "cl /nologo /LD template.c /Fe:template.dll"
    Write-Host "cl /nologo /LD hook.c /Fe:hook.dll"
    exit 0
}

# Default: MinGW-w64
Write-Host "Detecting MinGW-w64 toolchain..."

# Prefer explicit cross-prefixed GCC if available, fall back to gcc
$gccPrefixed = "x86_64-w64-mingw32-gcc"
$gccFallback = "gcc"
$useGcc = $null
if (Get-Command $gccPrefixed -ErrorAction SilentlyContinue) {
    $useGcc = $gccPrefixed
} elseif (Get-Command $gccFallback -ErrorAction SilentlyContinue) {
    $useGcc = $gccFallback
}

if (-not $useGcc) {
    Write-Host "Warning: MinGW-w64 gcc not found in PATH." -ForegroundColor Yellow
    Write-Host "Recommended: install MSYS2 and use the MinGW64 shell. See instructions below." -ForegroundColor Yellow
    Write-Host "MSYS2 quick install (run in PowerShell as admin):`n1) Download MSYS2 from https://www.msys2.org`n2) Follow the installer steps`n3) Open 'MSYS2 MinGW 64-bit' shell and run:`n    pacman -Syu`n    pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl`n" -ForegroundColor Yellow
    Write-Host "You can still run the script with MSVC by passing -msvc" -ForegroundColor Yellow
    exit 1
}

Write-Host "Using compiler: $useGcc"
Write-Host "Building with MinGW-w64 (example commands). If using MSYS2, run this script from the 'MSYS2 MinGW 64-bit' shell so headers/libs are found."

Write-Host "Compiling stealth_cryptor.c -> stealth_cryptor.exe"
# Link against OpenSSL; MSYS2 installs headers/libs under /mingw64/include and /mingw64/lib when using the MinGW64 shell
& $useGcc -O2 -march=native -o stealth_cryptor.exe stealth_cryptor.c -I/mingw64/include -L/mingw64/lib -lssl -lcrypto

Write-Host "Compiling binder.c -> binder.exe"
& $useGcc -O2 -march=native -o binder.exe binder.c

Write-Host "Compiling stub.c -> stub.exe"
& $useGcc -O2 -march=native -o stub.exe stub.c -Wl,--subsystem,windows -I/mingw64/include -L/mingw64/lib -lssl -lcrypto

Write-Host "Compiling template.c -> template.dll"
& $useGcc -O2 -march=native -shared -o template.dll template.c -Wl,--subsystem,windows -I/mingw64/include -L/mingw64/lib -lssl -lcrypto

Write-Host "Compiling hook.c -> hook.dll"
& $useGcc -O2 -march=native -shared -o hook.dll hook.c -Wl,--subsystem,windows

Write-Host "Build complete (note: ensure you run from MSYS2 MinGW64 shell or set /mingw64 include/lib paths)." -ForegroundColor Green
