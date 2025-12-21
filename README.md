# Chain_of_Trust 🔐

| Feature / Layer           | Kernel-gestütztes EDR-System | Cross-Platform EDR Map       | EDR-EXPLANATION Summary        |
|---------------------------|------------------------------|-------------------------------|--------------------------------|
| Platform Scope            | Windows (kernel-mode)        | Windows, Linux, macOS         | Windows-focused                |
| Monitoring Mechanism      | Kernel callbacks (OB, Ps...) | ETW, eBPF, EndpointSecurity   | ETW + Registry + MiniDump      |
| Process Protection        | Blocks ProtectedApp.exe      | Abstracted across OSes        | Self-healing + restart         |
| Encryption                | TPM-backed AES-GCM           | TLS for agent comms           | TPM + AES-256 + ECDSA          |
| Event Logging             | ETW with sampling             | Unified JSON schema           | Structured ETW events          |
| Deployment Strategy       | PowerShell + WDAC            | Intune, Ansible, MDM          | Intune + HLK automation        |
| Detection Engine          | Signature + heuristics       | Sigma/YARA-L + optional ML    | IOC + Defender ATP             |
| Response Actions          | Block access, restore files  | Kill process, quarantine      | Restart protected process      |
| Security Hardening        | CMake flags + signed driver  | WHQL, DKMS, Notarization      | Registry keys + WHQL           |
| Red Team Validation       | Not mentioned                | Atomic Red Team + benchmarks  | Azure DevOps pipeline          |
| Cloud Integration         | WDAC + TPM                   | SIEMs (Splunk, Sentinel)      | Defender ATP + Azure DevOps    |
| Scalability               | Single-platform              | Modular agents across OSes    | 10,000+ endpoints              |

---

## 📚 Dokumentation
Siehe Wiki & Diskussionen für Architekturdetails und Roadmap.

# Chain_of_Trust 🔐  
Chain-of-Trust für Windows-Treiber mit TPM & WDAC

[![Build](https://github.com/SHAdd0WTAka/Chain_of_Trust/actions/workflows/build.yml/badge.svg)](https://github.com/SHAdd0WTAka/Chain_of_Trust/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/SHAdd0WTAka/Chain_of_Trust)](https://github.com/SHAdd0WTAka/Chain_of_Trust/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/SHAdd0WTAka/Chain_of_Trust)](https://github.com/SHAdd0WTAka/Chain_of_Trust/releases)

## Features

- 🧩 Modularer CMake-Build mit vcpkg  
- 🔐 TPM-gestützte Vertrauensprüfung  
- 🛡️ WDAC-konforme Treibersignatur  
- ⚙️ Automatisierter CI-Workflow mit GitHub Actions

## Build & Test
```bash
git clone https://github.com/SHAdd0WTAka/Chain_of_Trust.git
cd Chain_of_Trust
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
ctest --test-dir build -C Release
```

---

## 🛠️ Build-Anleitung (Legacy / Manual)
1. Leeres Repo auf GitHub anlegen („Chain_of_Trust“).  
2. Alle Dateien aus dem Struktur-Block hineinkopieren.  
3. Commit & Push – GitHub Actions baut sofort.  

WHQL- / EV-Zertifikat eintragen → fertig für Produktion.

---

### License
EUPL-1.2 – free for commercial use, patent clause included.