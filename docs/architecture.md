# Architecture

```mermaid
graph TD;
  subgraph GUI
    V[View (tkinter)] --> Ctlr[Controller]
  end
  subgraph Core
    Ctlr --> M[CryptoModel]
    M --> KM[KeyManager]
    M --> VS[VaultStore]
    M --> IC[IntegrityChecker]
  end
  KM -->|derive_key| FK[Fernet / AES Key]
  VS -->|encrypt/decrypt| FK
  IC -->|HMAC/GCM tag| VS
``` 

* **KeyManager** – Argon2-id hasher + KDF wrappers; owns the symmetric key used for Fernet (`LSV1`) and AES-256-GCM (`LSV2`).  
* **VaultStore** – persists ciphertext, handles export/import and header parsing.  
* **IntegrityChecker** – verifies HMAC for `LSV1` vaults; integrity for `LSV2` vaults is provided by the built-in GCM tag.  
* **CryptoModel** – façade that orchestrates the three core services and exposes a simple API to the Controller. 