import subprocess
from pathlib import Path

BASE = Path.cwd()

def create_dirs():
    folders = [
        ".github/workflows", "src/edr_agent", "src/edr_kernel",
        "src/common", "cmake", "scripts", "policies"
    ]
    for folder in folders:
        Path(BASE / folder).mkdir(parents=True, exist_ok=True)

def write(path, content):
    Path(BASE / path).write_text(content.strip() + "\n", encoding="utf-8")

def git_init():
    subprocess.run(["git", "init"], check=True)
    subprocess.run(["git", "add", "."], check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], check=True)

def main():
    create_dirs()

    write("README.md", "# Chain_of_Trust\nOpen-source, kernel-backed, TPM-sealed EDR.")
    write("CMakeLists.txt", "cmake_minimum_required(VERSION 3.25)\nproject(Chain_of_Trust)")
    write("CMakePresets.json", """{
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
}""")

    write("vcpkg.json", """{
  "name": "chain-of-trust",
  "version": "1.0.0",
  "dependencies": [
    "detours",
    "gtest"
  ]
}""")

    write(".github/workflows/build.yml", """name: Build & Test
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
""")

    write("src/edr_agent/main.cpp", """#include <windows.h>
int main() {
    return 0;
}
""")

    write("src/edr_kernel/edrdrv.c", """#include <ntddk.h>
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    return STATUS_SUCCESS;
}
""")

    write("src/edr_kernel/edrdrv.inf", """[Version]
Signature="$WINDOWS NT$"
Class=Sample
ClassGuid={78A1C341-4539-11d3-B88D-00C04FAD5171}
Provider=%ManufacturerName%
DriverVer=09/20/2025,1.0.0.0

[Manufacturer]
%ManufacturerName%=Standard,NTx86,NTamd64

[Standard.NTx86]
%DeviceName%=Install, Root\\EDRDriver

[Standard.NTamd64]
%DeviceName%=Install, Root\\EDRDriver

[Strings]
ManufacturerName="Chain_of_Trust"
DeviceName="EDR Kernel Driver"
""")

    write("scripts/Build.ps1", """cmake --preset=ci-windows
cmake --build --preset=ci-windows --config Release
""")

    write("scripts/Install.ps1", """Write-Host "Installing EDR driver..."
pnputil /add-driver src\\edr_kernel\\edrdrv.inf /install
""")

    write("policies/WDAC_EDR.xml", """<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <PolicyName>Chain_of_Trust_EDR</PolicyName>
  <Rules>
    <!-- Add WDAC rules here -->
  </Rules>
</SiPolicy>
""")

    git_init()
    print("[+] Chain_of_Trust Repo erfolgreich generiert und initialisiert.")

if __name__ == "__main__":
    main()

