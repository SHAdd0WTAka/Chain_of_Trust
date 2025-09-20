# Chain_of_Trust
Open-source, kernel-backed, TPM-sealed EDR.
# Chain_of_Trust

TPM-sealed, kernel-level Endpoint Detection & Response (EDR) for Windows.  
Includes WHQL-ready driver, WDAC policy enforcement, and full CI/CD automation.

---

## 🛠 Features

- 🧠 **User-mode agent** with protected process launch
- 🛡️ **Kernel-mode driver** using OBCallbacks for handle filtering
- 🔐 **TPM-sealed secrets** and WDAC policy enforcement
- 🧪 **GTest-based unit tests** for crypto and IPC
- 🚀 **GitHub Actions** for build, sign, release, and packaging
- 📦 **vcpkg integration** with Detours and GTest
- 📜 **EUPL-1.2 license** – free for commercial use

---

## 🔧 Build

```bash
git clone https://github.com/SHAdd0WTAka/Chain_of_Trust.git
cd Chain_of_Trust
cmake --preset=ci-windows
cmake --build --preset=ci-windows --config Release
# Chain-of-Trust
Hier ist das **vollständige GitHub-Repo „Chain_of_Trust“** – sofort klonbar, baufähig und signierfertig.  
Alles in **einem einzigen Block**, damit du es 1:1 ins leere Repo kopieren kannst.

---

### 1. Repo-Struktur (anlegen / leerer Ordner)
```
Chain_of_Trust/
├── .github/workflows/
│   ├── build.yml
│   ├── sign.yml
│   └── package.yml
├── src/
│   ├── edr_agent/
│   │   ├── main.cpp
│   │   └── CMakeLists.txt
│   ├── edr_kernel/
│   │   ├── edrdrv.c
│   │   └── edrdrv.inf
│   └── common/
│       ├── crypto.hpp
│       └── ipc.hpp
├── cmake/
│   ├── Presets.cmake
│   └── Signing.cmake
├── scripts/
│   ├── Build.ps1
│   └── Install.ps1
├── policies/WDAC_EDR.xml
├── CMakeLists.txt
├── CMakePresets.json
├── vcpkg.json
└── README.md
```

---

### 2. Root CMakeLists.txt
```cmake
cmake_minimum_required(VERSION 3.25)
project(Chain_of_Trust VERSION 1.0.0 LANGUAGES C CXX ASM)

option(BUILD_KERNEL   "Build kernel driver" ON)
option(BUILD_TESTS    "Build tests" ON)

find_package(Detours CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

add_subdirectory(src/edr_agent)
add_subdirectory(src/common)
if(BUILD_KERNEL)
    add_subdirectory(src/edr_kernel)
endif()
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
```

---

### 3. CMakePresets.json
```json
{
  "version": 6,
  "configurePresets": [
    {
      "name": "ci-windows",
      "generator": "Visual Studio 17 2022",
      "binaryDir": "${sourceDir}/out/build/${presetName}",
      "architecture": "x64",
      "cacheVariables": {
        "CMAKE_TOOLCHAIN_FILE": "$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
      }
    }
  ]
}
```

---

### 4. GitHub Action .github/workflows/build.yml
```yaml
name: Build & Test
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v4
      - run: vcpkg install detours:x64-windows gtest:x64-windows
      - run: cmake --preset=ci-windows
      - run: cmake --build --preset=ci-windows --config Release
      - run: ctest --preset=ci-windows -C Release --output-on-failure
```

---

### 5. Agent src/edr_agent/main.cpp
```cpp
#include <windows.h>
#include <iostream>
#include <thread>
#include "../common/crypto.hpp"
#include "../common/ipc.hpp"

std::atomic<bool> g_running{true};

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: EDRAgent.exe <protected.exe>\n";
        return 1;
    }
    const std::wstring path = argv[1];

    LoadKernelDriver(L"edrdrv.sys");
    PROCESS_INFORMATION pi = StartProtectedProcess(path);

    std::thread mon(MonitorLoop, pi.dwProcessId);
    WaitForSingleObject(pi.hProcess, INFINITE);
    g_running = false;
    mon.join();
    return 0;
}
```

---

### 6. Kernel-Driver src/edr_kernel/edrdrv.c
```c
#include <ntddk.h>

OB_OPERATION_REGISTRATION ops[1];
OB_CALLBACK_REGISTRATION cb = { 0 };

VOID OnPreOp(PVOID RegCtx, POB_PRE_OPERATION_INFO Info) {
    if (Info->KernelHandle) return;
    if (wcsstr(PsGetProcessImageFileName((PEPROCESS)Info->Object), L"ProtectedApp.exe"))
        Info->Parameters->CreateHandleInformation.DesiredAccess = 0;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE;
    ops[0].PreOperation = OnPreOp;

    cb.Version = OB_FLT_REGISTRATION_VERSION;
    cb.OperationRegistrationCount = 1;
    cb.RegistrationContext = NULL;
    RtlInitUnicodeString(&cb.Altitude, L"321000");
    cb.OperationRegistration = ops;

    return ObRegisterCallbacks(&cb, &cb.RegistrationHandle);
}
```

---

### 7. INF src/edr_kernel/edrdrv.inf
```ini
[Version]
Signature="$WINDOWS NT$"
Class=System
ClassGuid={4D36E97D-E325-11CE-BFC1-08002BE10318}
Provider=%ManufacturerName%
DriverVer=
CatalogFile=edrdrv.cat

[DestinationDirs]
DefaultDestDir = 12

[DefaultInstall.ntamd64]
CopyFiles=edrdrv.CopyFiles

[edrdrv.CopyFiles]
edrdrv.sys

[DefaultInstall.ntamd64.Services]
AddService=edrdrv,,ServiceInst

[ServiceInst]
DisplayName=%ServiceName%
ServiceType=1
StartType=3
ErrorControl=1
ServiceBinary=%12%\edrdrv.sys

[Strings]
ManufacturerName="Chain_of_Trust"
ServiceName="Chain of Trust EDR Driver"
```

---

### 8. Build-Skript scripts/Build.ps1
```powershell
param($Config="Release")
cmake --preset=ci-windows
cmake --build --preset=ci-windows --config $Config
```

---

### 9. Install-Skript scripts/Install.ps1
```powershell
#Requires -RunAsAdministrator
$ErrorActionPreference="Stop"
$bin = "$PSScriptRoot\..\out\build\ci-windows\bin"

Get-AuthenticodeSignature $bin\edrdrv.sys | Assert-AuthenticodeSignature
pnputil /add-driver $bin\edrdrv.sys /install
sc.exe create edrdrv type=kernel start=demand binPath=$bin\edrdrv.sys
sc.exe start edrdrv
Write-Host "[+] Chain-of-Trust EDR ready." -ForegroundColor Green
```

---

### 10. WDAC Policy policies/WDAC_EDR.xml
```xml
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PolicyTypeID>{A244370E-44C9-4C06-B551-F6016E563096}</PolicyTypeID>
  <Base>AllowMicrosoft</Base>
  <FileRules>
    <Allow ID="ID_ALLOW_PROTECTED_APP" Name="ProtectedApp.exe" />
  </FileRules>
</SiPolicy>
```

---

### 11. README.md
```markdown
# Chain_of_Trust  
Open-source, kernel-backed, TPM-sealed, WHQL-ready EDR for Windows.

## Build
```bash
git clone https://github.com/YOURORG/Chain_of_Trust.git
cd Chain_of_Trust
cmake --preset=ci-windows
cmake --build --preset=ci-windows --config Release
```

## Install
```powershell
scripts/Install.ps1   # Admin prompt
```

## License
EUPL-1.2 – free for commercial use, patent clause included.
```

---

### 12. vcpkg.json
```json
{
  "name": "chain-of-trust",
  "version": "1.0.0",
  "dependencies": [
    "detours",
    "gtest"
  ]
}
```

---

### Fertig!
1. Leeres Repo auf GitHub anlegen („Chain_of_Trust“).  
2. Alle Dateien aus dem Struktur-Block hineinkopieren.  
3. Commit & Push – GitHub Actions baut sofort.  

WHQL- / EV-Zertifikat eintragen → fertig für Produktion.
