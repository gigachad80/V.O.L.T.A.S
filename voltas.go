package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// --- CONFIGURATION & STYLES ---

var (
	// Colors
	colorGreen  = lipgloss.Color("#04B575")
	colorPurple = lipgloss.Color("#7D56F4")
	colorYellow = lipgloss.Color("#FFD700")
	colorDark   = lipgloss.Color("#1A1A1A")
	colorText   = lipgloss.Color("#FFFFFF")
	colorGray   = lipgloss.Color("#444444")

	// Layout Styles
	docStyle = lipgloss.NewStyle().Margin(1, 2)

	// Tab Styles
	activeTabStyle = lipgloss.NewStyle().
			Foreground(colorDark).Background(colorGreen).
			Padding(0, 1).Bold(true).MarginRight(1)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(colorText).Background(colorGray).
				Padding(0, 1).MarginRight(1)

	// Status Bar Styles
	statusLabelStyle = lipgloss.NewStyle().
				Foreground(colorDark).Background(colorYellow).
				Padding(0, 1).Bold(true)

	statusInfoStyle = lipgloss.NewStyle().
			Foreground(colorText).Background(colorGray).
			Padding(0, 1)

	// Output Footer
	footerStyle = lipgloss.NewStyle().
			Foreground(colorText).Background(colorDark).
			Padding(0, 1).MarginTop(1)
)

// --- DATA MODELS ---

type ToolCategory string

const (
	CatAcquisition = "Acquisition"
	CatLive        = "Live Scan"
	CatMemProcFS   = "MemProcFS"
	CatProcess     = "Process"
	CatObjects     = "Objects"
	CatNetwork     = "Network"
	CatInjection   = "Injection"
	CatRootkits    = "Rootkits"
	CatExtraction  = "Extraction"
)

type toolItem struct {
	title       string
	desc        string
	category    ToolCategory
	command     string
	defaultArgs string
	isExternal  bool
}

func (t toolItem) Title() string       { return t.title }
func (t toolItem) Description() string { return fmt.Sprintf("[%s] %s", t.category, t.desc) }
func (t toolItem) FilterValue() string { return "" }

// --- MAIN APPLICATION MODEL ---

type sessionState int

const (
	StateList sessionState = iota
	StateConfig
	StateRunning
	StateOutput
)

type tickMsg time.Time

type model struct {
	// Settings
	memImagePath string
	outputDir    string
	csvMode      bool

	// State
	state  sessionState
	ready  bool
	width  int
	height int

	// Components
	list     list.Model
	viewport viewport.Model
	progress progress.Model

	// Config Inputs
	inputImage textinput.Model
	inputOut   textinput.Model

	// Execution Data
	currentTool   toolItem
	outputContent string
	savedFile     string
}

func initialModel() model {
	// 1. Define Tools
	tools := []toolItem{
		// --- ACQUISITION ---
		{"WinPmem", "Live capture (Admin)", CatAcquisition, "winpmem_mini_x64.exe", "-d mem.img", true},
		{"DumpIt", "Magnet DumpIt", CatAcquisition, "DumpIt.exe", "/TYPE DMP /OUTPUT mem.img", true},

		// --- LIVE SCANNING ---
		{"Moneta", "Malware Scanner", CatLive, "moneta64.exe", "-m ioc -p * --filter * -d", true},
		{"HollowsHunter", "Scan implants", CatLive, "hollows_hunter64.exe", "/pid <PID> /dir .\\Output", true},
		{"InjThreadEx", "Get-InjectedThreadEx", CatLive, "Get-InjectedThreadEx.exe", "", true},

		// --- MEMPROCFS ---
		{"MemProcFS", "Mount & Forensic Mode 1", CatMemProcFS, "MemProcFS.exe", "-device <IMAGE> -forensic 1", true},

		// --- ROGUE PROCESSES ---
		{"PsList", "List Processes", CatProcess, "windows.pslist.PsList", "", false},
		{"PsScan", "Deep Process Scan", CatProcess, "windows.psscan.PsScan", "", false},
		{"PsTree", "Process Tree", CatProcess, "windows.pstree.PsTree", "", false},

		// --- PROCESS OBJECTS ---
		{"DllList", "List DLLs", CatObjects, "windows.dlllist.DllList", "--pid <PID>", false},
		{"CmdLine", "Command Lines", CatObjects, "windows.cmdline.CmdLine", "", false},
		{"GetSIDs", "Process SIDs", CatObjects, "windows.getsids.GetSIDs", "", false},
		{"Handles", "Open Handles", CatObjects, "windows.handles.Handles", "--pid <PID>", false},

		// --- NETWORK ---
		{"NetStat", "Network Structures", CatNetwork, "windows.netstat.NetStat", "", false},
		{"NetScan", "Deep Net Scan", CatNetwork, "windows.netscan.NetScan", "--include-corrupt", false},

		// --- CODE INJECTION & YARA ---
		{"Malfind", "Suspicious RWX", CatInjection, "windows.malfind.Malfind", "--dump", false},
		{"LdrModules", "Unlinked DLLs", CatInjection, "windows.ldrmodules.LdrModules", "", false},
		{"VadYaraScan", "Scan with YARA File", CatInjection, "windows.vadyarascan.VadYaraScan", "--yara-file <RULES>", false},

		// --- ROOTKITS ---
		{"Modules", "Kernel Drivers", CatRootkits, "windows.modules.Modules", "", false},
		{"ModScan", "Hidden Modules (Rootkits)", CatRootkits, "windows.modscan.ModScan", "--dump", false},
		{"SSDT", "Service Descriptor Table", CatRootkits, "windows.ssdt.SSDT", "", false},
		{"DriverIrp", "Driver IRP Hooks", CatRootkits, "windows.driverirp.DriverIrp", "", false},

		// --- DUMP / EXTRACTION ---
		{"FileScan", "Find Files (MFT/Cache)", CatExtraction, "windows.filescan.FileScan", "", false},
		{"SvcScan", "Windows Services", CatExtraction, "windows.svcscan.SvcScan", "", false},
		{"MemMap", "Memory Map", CatExtraction, "windows.memmap.Memmap", "--pid <PID>", false},
		{"DumpFiles", "Extract Files", CatExtraction, "windows.dumpfiles.DumpFiles", "--pid <PID>", false},
	}

	// 2. Setup List
	items := make([]list.Item, len(tools))
	for i, t := range tools {
		items[i] = t
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "V.O.L.T.A.S"
	l.Styles.Title = lipgloss.NewStyle().Foreground(colorGreen).Bold(true).MarginLeft(2)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	// 3. Setup Progress Bar
	prog := progress.New(progress.WithDefaultGradient())
	prog.Width = 40

	// 4. Setup Inputs
	ti1 := textinput.New()
	ti1.Placeholder = "Path to memory image"
	ti2 := textinput.New()
	ti2.Placeholder = "Output Directory"

	return model{
		list:       l,
		progress:   prog,
		inputImage: ti1,
		inputOut:   ti2,
		state:      StateList,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// --- UPDATE LOOP ---

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	if m.memImagePath == "" && m.state != StateConfig {
		m.state = StateConfig
		m.inputImage.Focus()
	}

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v-4)
		m.viewport = viewport.New(msg.Width-h, msg.Height-v-4)
		m.ready = true

	case tickMsg:
		if m.state == StateRunning {
			if m.progress.Percent() >= 1.0 {
				m.progress.SetPercent(0.0)
			} else {
				cmd = m.progress.IncrPercent(0.02)
			}
			return m, tea.Batch(tickCmd(), cmd)
		}

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd

	case commandResultMsg:
		m.outputContent = msg.output
		m.savedFile = msg.filename
		m.viewport.SetContent(msg.output)
		m.state = StateOutput
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			if m.state == StateList {
				m.state = StateConfig
				m.inputImage.Focus()
			} else if m.state == StateConfig {
				m.state = StateList
				m.inputImage.Blur()
				m.inputOut.Blur()
			}
			return m, nil

		case "ctrl+c":
			return m, tea.Quit
		}

		switch m.state {
		case StateList:
			if msg.String() == "x" {
				m.csvMode = !m.csvMode
			}
			if msg.String() == "enter" {
				i, ok := m.list.SelectedItem().(toolItem)
				if ok {
					// --- FIXED LOGIC: HANDLE INPUT BEFORE STARTING PROGRESS BAR ---
					args := i.defaultArgs

					// 1. Handle PID Input
					if strings.Contains(args, "<PID>") {
						var pid string
						huh.NewForm(huh.NewGroup(huh.NewInput().Title("Target PID").Value(&pid))).Run()
						if pid == "" {
							return m, nil // Abort if empty
						}
						args = strings.ReplaceAll(args, "<PID>", pid)
					}

					// 2. Handle YARA Rules Input
					if strings.Contains(args, "<RULES>") {
						var rulesPath string
						huh.NewForm(huh.NewGroup(
							huh.NewInput().
								Title("Path to YARA Rules File").
								Placeholder("D:\\Rules\\malware.yar").
								Value(&rulesPath),
						)).Run()
						if rulesPath == "" {
							return m, nil // Abort
						}
						args = strings.ReplaceAll(args, "<RULES>", cleanPath(rulesPath))
					}

					// 3. Handle MemProcFS Image Injection
					if strings.Contains(args, "<IMAGE>") {
						args = strings.ReplaceAll(args, "<IMAGE>", cleanPath(m.memImagePath))
					}

					// UPDATE TOOL WITH FILLED ARGS
					i.defaultArgs = args

					// NOW START EXECUTION
					m.currentTool = i
					m.state = StateRunning
					m.progress.SetPercent(0.0)
					return m, tea.Batch(tickCmd(), m.generateCommand(i))
				}
			}
			m.list, cmd = m.list.Update(msg)
			cmds = append(cmds, cmd)

		case StateOutput:
			if msg.String() == "esc" || msg.String() == "q" {
				m.state = StateList
			}
			m.viewport, cmd = m.viewport.Update(msg)
			cmds = append(cmds, cmd)

		case StateConfig:
			if msg.String() == "enter" {
				if m.inputImage.Focused() {
					m.inputImage.Blur()
					m.inputOut.Focus()
				} else {
					m.memImagePath = cleanPath(m.inputImage.Value())
					m.outputDir = cleanPath(m.inputOut.Value())
					m.state = StateList
				}
			}
			var cmd1, cmd2 tea.Cmd
			m.inputImage, cmd1 = m.inputImage.Update(msg)
			m.inputOut, cmd2 = m.inputOut.Update(msg)
			cmds = append(cmds, cmd1, cmd2)
		}
	}

	return m, tea.Batch(cmds...)
}

// --- VIEW ---

func (m model) View() string {
	if !m.ready {
		return "Loading..."
	}

	tabTools := inactiveTabStyle.Render(" 1. TOOLS ")
	tabConfig := inactiveTabStyle.Render(" 2. SETTINGS ")
	if m.state == StateList || m.state == StateRunning || m.state == StateOutput {
		tabTools = activeTabStyle.Render(" 1. TOOLS ")
	} else {
		tabConfig = activeTabStyle.Render(" 2. SETTINGS ")
	}
	header := lipgloss.JoinHorizontal(lipgloss.Top, tabTools, tabConfig)

	var content string

	switch m.state {
	case StateList:
		modeText := "PRETTY (Press X for CSV)"
		if m.csvMode {
			modeText = "CSV EXPORT (Press X to reset)"
		}
		imgName := filepath.Base(m.memImagePath)
		if m.memImagePath == "" {
			imgName = "None"
		}

		modeBadge := statusLabelStyle.Render(" MODE: " + modeText + " ")
		imgBadge := statusInfoStyle.Render(" Image: " + imgName + " ")
		statusBar := lipgloss.JoinHorizontal(lipgloss.Top, modeBadge, imgBadge)

		content = lipgloss.JoinVertical(lipgloss.Left,
			statusBar,
			m.list.View(),
		)

	case StateConfig:
		content = fmt.Sprintf("\n  CONFIGURATION\n\n  Target Image:\n  %s\n\n  Output Directory:\n  %s\n\n  [Enter] Save & Return",
			m.inputImage.View(),
			m.inputOut.View(),
		)

	case StateRunning:
		pad := strings.Repeat(" ", 10)
		content = fmt.Sprintf("\n\n%sProcessing %s...\n\n%s%s\n\n%s(Please wait...)",
			pad, m.currentTool.title, pad, m.progress.View(), pad)

	case StateOutput:
		title := fmt.Sprintf(" OUTPUT: %s | SAVED TO: %s ", m.currentTool.title, m.savedFile)
		banner := lipgloss.NewStyle().Background(colorPurple).Foreground(colorText).Bold(true).Render(title)
		content = fmt.Sprintf("%s\n%s\n%s", banner, m.viewport.View(), footerStyle.Render(" [Esc] Back | [Arrows] Scroll "))
	}

	return docStyle.Render(lipgloss.JoinVertical(lipgloss.Left, header, content))
}

// --- HELPERS ---

func cleanPath(path string) string {
	return strings.Trim(path, "\"")
}

func resolveBinary(bin string) (string, bool) {
	if _, err := os.Stat(bin); err == nil {
		if runtime.GOOS == "windows" {
			return ".\\" + bin, true
		}
		return "./" + bin, true
	}
	if _, err := exec.LookPath(bin); err == nil {
		return bin, true
	}
	return bin, false
}

// --- COMMAND GENERATION ---

type commandResultMsg struct {
	output   string
	filename string
}

func (m model) generateCommand(t toolItem) tea.Cmd {
	return func() tea.Msg {
		imgName := filepath.Base(m.memImagePath)
		imgName = strings.TrimSuffix(imgName, filepath.Ext(imgName))

		ext := "txt"
		if m.csvMode {
			ext = "csv"
		}

		saveFilename := fmt.Sprintf("%s-%s.%s", imgName, t.title, ext)
		savePath := filepath.Join(m.outputDir, saveFilename)

		// ARGS ARE NOW ALREADY PREPARED IN UPDATE LOOP
		args := t.defaultArgs

		// --- PRE-FLIGHT CHECK ---
		var binName string
		if !t.isExternal {
			binName = "vol"
			if runtime.GOOS == "windows" {
				binName = "vol.exe"
			}
		} else {
			binName = t.command
		}

		resolvedBin, exists := resolveBinary(binName)
		if !exists {
			return commandResultMsg{
				output:   fmt.Sprintf("\n ❌ ERROR: Tool '%s' not found.\n Please download and place it in the application folder.", binName),
				filename: "Error",
			}
		}

		// --- EXECUTION ---
		var cmd *exec.Cmd
		var cmdStr string

		if !t.isExternal {
			cmdArgs := []string{"-f", cleanPath(m.memImagePath), "-o", cleanPath(m.outputDir), t.command}
			if m.csvMode {
				cmdArgs = append([]string{"-r", "csv"}, cmdArgs...)
			}
			if len(args) > 0 {
				cmdArgs = append(cmdArgs, strings.Fields(args)...)
			}
			cmd = exec.Command(resolvedBin, cmdArgs...)
			cmdStr = fmt.Sprintf("%s %s", resolvedBin, strings.Join(cmdArgs, " "))
		} else {
			// External Tools
			cmd = exec.Command(resolvedBin, strings.Fields(args)...)
			cmdStr = fmt.Sprintf("%s %s", resolvedBin, args)
		}

		outBytes, err := cmd.CombinedOutput()
		output := string(outBytes)

		// --- AUTO SAVE ---
		var saveMsg string
		if err == nil {
			os.MkdirAll(m.outputDir, os.ModePerm)
			os.WriteFile(savePath, outBytes, 0644)
			saveMsg = "Saved."
		} else {
			saveMsg = "Failed."
		}

		display := fmt.Sprintf("COMMAND: %s\nMODE: %s | FILE: %s (%s)\n%s\n\n%s",
			cmdStr, strings.ToUpper(ext), saveFilename, saveMsg, strings.Repeat("-", 60), output)

		return commandResultMsg{output: display, filename: saveFilename}
	}
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
