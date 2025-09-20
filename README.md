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
