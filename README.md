
🚀 Project Name : V.O.L.T.A.S
===============

#### Volatility Orchestration & Live Triage Analysis Suite : A TUI-based Memory Forensics, Malware Analysis & Threat Hunting Framework built in Go.

![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-purple.svg)
![Go](https://img.shields.io/badge/Made%20with-Go-00ADD8.svg?style=flat&logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-gray.svg)
<a href="https://github.com/gigachad80/V.O.L.T.A.S/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>

## Table of Contents

* [📌 Overview](#-overview)
* [✨ Features](#-features)
* [🎯 Before & After V.O.L.T.A.S](#-before--after-voltas)
* [🛠️ Dependencies & Requirements](#%EF%B8%8F-dependencies--requirements)
* [📥 Installation Guide](#-installation-guide)
* [🚀 Usage](#-usage)
* [🔧 Technical Details](#-technical-details)
* [🤔 Why This Name?](#-why-this-name)
* [⌚ Development Time](#-development-time)
* [🙃 Why I Created This](#-why-i-created-this)
* [🙏 Credits & Inspiration](#-credits--inspiration)
* [📞 Contact](#-contact)
* [📄 License](#-license)

### 📌 Overview

**V.O.L.T.A.S** is a blazing-fast TUI (Terminal User Interface) orchestration framework designed for Forensic Analysts, Threat Hunters, and Incident Responders. 

Instead of memorizing 50+ complex Volatility commands, managing long file paths, or manually running individual binaries for live scanning, V.O.L.T.A.S unifies everything into a single **Command & Control Dashboard**. It automates the SANS Memory Forensics workflow, allowing you to switch between Acquisition, Live Scanning, and Deep Analysis in seconds.

**Key Capabilities:**
* **Orchestration:** Controls Volatility 3, Moneta, WinPmem, and HollowsHunter from one screen.
* **Smart Context:** Remembers your Image Path and Output Directory (no more re-typing).
* **Live Triage:** Integrated support for detecting code injection and beacons in real-time.
* **Auto-Save:** Automatically logs output to `.txt` or exports to `.csv`.

### ✨ Features

### 🎯 Smart Workflow
- **Unified Dashboard** - Navigate via Tabs (`Tools` vs `Settings`) and Arrow Keys.
- **Pre-Flight Checks** - Automatically checks if tools exist before running (prevents crashes).
- **Dynamic Inputs** - Smartly asks for PIDs or YARA rules only when the specific plugin needs them.
- **Cross-Platform Logic** - Automatically disables Windows-only tools (like Moneta) when running on Linux.
- **Auto-Logging** - Every command output is saved as `ImageName-ToolName.txt`.
- **CSV Mode** (`Press X`) - Toggle between pretty terminal output and CSV export for Excel.


### 🎯 Before & After V.O.L.T.A.S

| Aspect | 😫 Before (The Command Line Hell) | ✨ After V.O.L.T.A.S (The Dashboard) |
|--------|-------------------------------------|--------------------------------|
| **Commands** | 😤 Typing `python vol.py -f "D:\Case\Mem.dmp" -o "C:\Out" windows.psscan` every single time | 🚀 Select `PsScan`, Press `Enter`. Done. |
| **Workflow** | 🤯 Switching between 3 different CMD windows for Acquisition, Volatility, and Moneta | 😎 All tools in one menu. Tab to switch contexts. |
| **Data** | ⏰ Manually piping output `> output.txt` or losing data in the terminal scrollback | ⚡ Auto-saved to organized files immediately. |
| **Reliability** | ❌ Typos in file paths or plugin names cause errors | ✅ Paths are stored in memory. Commands are pre-configured. |

### 💡 Why This Matters

Real-world Incident Response is messy. Your desktop usually looks like a disaster zone of open terminals, notepads, and PDF guides.

| Without V.O.L.T.A.S | With V.O.L.T.A.S |
| :--- | :--- |
| ❌ **Fragmented:** Volatility is Python. WinPmem is an EXE. Moneta is another EXE. You need 3 different shells open. | ✅ **Unified:** One dashboard controls the Python script, the acquisition binary, and the live scanners. |
| ❌ **Repetitive:** Typing `-f "D:\Evidence\Case\Mem.dmp"` fifty times a day. | ✅ **Smart:** Set the image path **once**. The tool injects it into every command automatically. |
| ❌ **Volatile:** If you close your terminal, you lose your command history and outputs. | ✅ **Persistent:** All outputs are automatically saved to text files for your report. |



### 🛠️ Dependencies & Requirements

V.O.L.T.A.S is an **Orchestrator**. It does not contain the engines inside it. You must download the standard forensic tools and place them in the same folder as `voltas.exe`.

**⚠️ REQUIRED EXECUTABLES (Download & Place in Root Folder):**

| Tool | Filename Required | Purpose |
| :--- | :--- | :--- |
| **Volatility 3** | `vol.exe` | The Core Analysis Engine. |
| **WinPmem** | `winpmem_mini_x64.exe` | For Memory Acquisition. |
| **DumpIt** | `DumpIt.exe` | Alternative Acquisition. |
| **Moneta** | `moneta64.exe` | Live Malware Scanning. |
| **HollowsHunter** | `hollows_hunter64.exe` | Scan for implants/hooks. |
| **InjThread** | `Get-InjectedThreadEx.exe` | Thread Injection detection. |
| **MemProcFS** | `MemProcFS.exe` | High-speed triage mounting. |

> **Note for Linux Users:** You only need `vol` (Volatility). The `.exe` tools (Moneta, WinPmem) are Windows-exclusive and those buttons will be disabled/hidden logic on Linux.

### 📥 Installation Guide

**Step 1: Build from Source or Download from Releases**
```bash
git clone https://github.com/gigachad80/V.O.L.T.A.S
cd VOLTAS
go mod tidy
go build -ldflags="-s -w" -o volta.exe
```
OR 

For downloading : Download the latest binary from the [releases](https://github.com/gigachad80) page and add it to your PATH.


**Step 2: Folder Setup**
1. Create a folder `C:\ForensicTools`. If you are on Linux , set it to `/usr/local/bin/`
2. Move `voltas.exe` there.
3. Move all the dependency `.exe` files (listed above) into that same folder.
4. Run `voltas.exe`.

### 🚀 Usage

**Navigation:**
*   **`Tab`**: Switch between **TOOLS** list and **SETTINGS**.
*   **`Up/Down`**: Navigate the menu.
*   **`Enter`**: Select a tool / Run command.
*   **`X`**: Toggle CSV Export Mode.
*   **`Esc`**: Go Back.

**Typical Workflow:**
1.  Launch V.O.L.T.A.S.
2.  Press `Tab` to go to **Settings**.
3.  Paste your Memory Image path (e.g., `D:\Dump.mem`).
4.  Press `Tab` to go back to **Tools**.
5.  Select **PsTree** to see processes.
6.  Select **Malfind** to hunt injections.

### 🔧 Technical Details

- **Language:** Go (Golang)
- **UI Framework:** [Bubble Tea](https://github.com/charmbracelet/bubbletea) & [Lipgloss](https://github.com/charmbracelet/lipgloss)
- **Architecture:** State-machine based TUI with async command execution.
- **Safety:** Implements pre-flight binary checks to prevent runtime panics if tools are missing.

### 🤔 Why This Name?

**V.O.L.T.A.S**
**V**olatility **O**rchestration & **L**ive **T**riage **A**nalysis **S**uite.

Also...  "Voltas" is a very famous Air Conditioner brand. It keeps things cool. Just like this tool keeps you cool during a heated Incident Response scenario. ❄️😎

### ⌚ Development Time

Roughly **1 hr 58 min 38 sec** of coding, adding more features editing README , and fighting with the progress bar logic to make it look smooth.

### 🙃 Why I Created This

I was deep into studying **Memory Forensics** (learning about VAD trees, PTEs, and Rootkits). I realized that while the *concepts* are fascinating, the *process* is painful.

I found myself typing the same 50-character commands over and over again. I looked at the **SANS Cheat Sheet** and thought: *"Why isn't there a tool that just follows this PDF automatically?"*

So I built it. I wanted to focus on **Finding Evil**, not typing file paths.

### 🙏 Credits & Inspiration

This project relies entirely on the giants of the industry. V.O.L.T.A.S is just the conductor; they are the musicians.

*   **SANS Institute:** Specifically the **SANS FOR508 Memory Forensics Cheat Sheet** by Chad Tilbury. This tool is literally a coded version of that PDF.
*   **The Volatility Foundation:** For building the world's best memory framework.
*   **Forrest Orr:** For Moneta (an absolute beast of a tool).
*   **Hasherezade:** For HollowsHunter.

*Disclaimer: This is an independent open-source project and is not affiliated with SANS or the Volatility Foundation.*

### 📞 Contact

📧 Email: **pookielinuxuser@tutamailcom**

### 📄 License

**MIT License** 

**Made with ❤️ in Go** - For the Blue Team. 🛡️
If V.O.L.T.A.S helped you streamline your forensics workflow, please consider **giving it a star!** ⭐ 
It helps others find the project and motivates me to develop more projects🥹🥹😭😭
````
