#!/bin/bash
echo "[+] Populating Chain_of_Trust project files..."

write() {
  mkdir -p "$(dirname "$1")"
  echo "$2" > "$1"
  echo "✔ $1"
}

write ".github/workflows/build.yml" \
"name: Build & Test
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
      - run: ctest --preset=ci-windows -C Release --output-on-failure"

write "tests/agent_test.cpp" \
"#include <gtest/gtest.h>
#include \"../src/common/crypto.hpp\"
TEST(CryptoTest, EncryptDecrypt) {
    std::string input = \"ChainOfTrust\";
    auto encrypted = Encrypt(input);
    auto decrypted = Decrypt(encrypted);
    ASSERT_EQ(decrypted, input);
}"

write ".gitignore" \
"out/
*.obj
*.exe
*.log
*.pdb
*.ilk
*.user
.vscode/
*.zip"

write "LICENSE" \
"European Union Public Licence v.1.2
You may use, modify and distribute this software freely, including for commercial use.
Patent clause included."

write "docs/ThreatModel.md" \
"# Threat Model – Chain_of_Trust
## Assets
- ProtectedApp.exe
- Kernel Driver (edrdrv.sys)
- IPC Channels
- TPM-Sealed Secrets
## Threats
- Handle spoofing
- Driver tampering
- IPC hijacking
- Unauthorized access
## Mitigations
- OBCallbacks for handle filtering
- WDAC policy enforcement
- TPM-sealed config
- Code signing with EV cert"

echo "[✓] All files populated. Ready to commit!"

