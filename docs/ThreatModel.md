# Threat Model – Chain_of_Trust
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
- Code signing with EV cert
