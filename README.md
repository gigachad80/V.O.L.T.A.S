# V.O.L.T.A.S
### Volatility Orchestration & Live Triage Analysis Suite

> **🚧 Coming Soon:** Initial Release v1.0 arriving within a week.

V.O.L.T.A.S is a TUI-based **Memory Forensics & Threat Hunting Orchestration Framework** built in Go. It automates the SANS workstation workflow by unifying Volatility 3, live scanning, and acquisition tools into a single dashboard.

---

### 🛠️ Dependencies (Prerequisites)
V.O.L.T.A.S acts as an orchestrator. You must download the following executables and place them in the same folder as `VOLTAS.exe`:

*   **`vol.exe`** (Volatility 3 Standalone)
*   **`winpmem_mini_x64.exe`** (Acquisition)
*   **`DumpIt.exe`** (Acquisition)
*   **`moneta64.exe`** (Live Scanning)
*   **`hollows_hunter64.exe`** (Live Scanning)
*   **`Get-InjectedThreadEx.exe`** (Live Scanning)
*   **`MemProcFS.exe`** (Triage)

---

### 🐧 Compatibility Note
**Windows is highly recommended.**

*   **Windows:** All features (Acquisition, Live Scanning, Analysis) work out of the box.
*   **Linux:** Only `Volatility` based analysis modules will work. Live Scanning and Acquisition tools (`.exe` binaries) are Windows-exclusive and will be disabled.
