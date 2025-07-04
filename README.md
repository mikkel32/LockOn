# 🔒 Lock On - Intelligent Folder Security System

![Lock On Banner](assets/banner.png)

Lock On is an advanced folder security monitoring system that uses intelligent pattern analysis to protect your files from malicious activities. With real-time monitoring, AI-powered threat detection, and aggressive countermeasures, Lock On ensures your data stays safe.

## ✨ Features

### 🛡️ Advanced Protection
- **Real-time Monitoring**: Continuously watches folder activities for suspicious behavior
- **AI Pattern Recognition**: Intelligent analysis of file operations and process behaviors
- **Multi-layered Security**: File scanning, process monitoring, and network protection
- **Honeypot System**: Deploy decoy files to catch malicious actors
- **Concurrent Scanning**: Uses multiple threads to rapidly baseline files
- **Adaptive Watchlist Scanning**: Watchlist interval shortens when new threats appear
- **CLI File Tree**: Generate an ASCII tree of monitored files from the command line
- **CLI Statistics**: Summarize logged events and threats at a glance
- **Process & Network Logging**: Suspicious processes and network connections are stored in the database

### 🧠 Intelligence Engine
- **Pattern-based Detection**: Recognizes ransomware, trojans, and other malware patterns
- **Behavioral Analysis**: Identifies suspicious activities based on behavior patterns
- **Machine Learning**: Adaptive threat detection that learns from events
- **YARA Integration**: Built-in malware signatures with customizable rules, including the EICAR test pattern and macro detection
- **Encoded Command Detection**: Spots base64-encoded PowerShell or shell commands
- **Reverse Shell Detection**: Identifies common bash or netcat reverse shells
- **PowerView and Invoke-Shellcode Detection**: Spots offensive PowerShell frameworks and shellcode loaders
- **Invoke-Obfuscation and Empire Detection**: Identifies advanced PowerShell attack frameworks
- **PsExec and MSBuild Detection**: Flags lateral-movement and malicious build abuse
- **InstallUtil Abuse Detection**: Detects persistence via InstallUtil commands
- **Shellcode Loader Detection**: Flags VirtualAllocEx/WriteProcessMemory sequences
- **Process Hollowing Detection**: Identifies NtUnmapViewOfSection and CreateRemoteThread combos
- **RAT Detection**: Identifies tools like njRAT, DarkComet and AgentTesla
- **Packed Binary Detection**: Spots UPX-packed executables
- **Unsigned Binary Detection**: Flags unsigned Windows executables
- **Archive Scanning**: Detects malicious macros and executables inside ZIP-based formats
- **Downloader Detection**: Flags certutil or rundll32 commands used for malware retrieval
- **Suspicious IP Monitoring**: Alerts on embedded IP addresses with port numbers
- **Deep YARA Scanning**: In-memory scanning of file contents and archives using custom rules
- **Process Command-Line Scanning**: Flags malicious payloads in running processes
- **Network Connection Scanning**: Detects suspicious outbound ports or IP addresses
- **Real-time Network Monitor**: Background thread flags suspicious outbound connections
- **Connection Risk Analysis**: Suspicious IPs and ports are classified with threat levels using `PatternAnalyzer`
- **Connection Event Caching**: Duplicate alerts are suppressed with a short-term cache
- **Debug Privilege Elevation**: Network monitor automatically acquires `SeDebugPrivilege` on Windows for deeper inspection
- **Meterpreter/CobaltStrike Detection**: Identifies penetration testing tool artifacts
- **Netsh Tunneling Detection**: Spots firewall or portproxy commands used for C2
- **Unified Hash and YARA Scanning**: Central scanner hashes files and applies signatures
- **Webhook URL Detection**: Flags exfiltration via Discord, Pastebin or GitHub webhooks
- **Cached Scanning**: Reuses file scan results to speed up repeated checks
- **Persistent Baseline Hashes**: File hashes are stored in the database and reused across runs
- **AutoIt Detection**: Identifies compiled AutoIt scripts
- **Keylogger API Detection**: Flags binaries using keystroke APIs
- **Discord Token Stealer Detection**: Spots token-stealing payloads

### ⚡ Response System
- **Automatic Quarantine**: Isolates threats instantly with encryption
- **Process Termination**: Kills malicious processes immediately
- **Emergency Lockdown**: Protects folders during active attacks
- **File Recovery**: Restore files from secure backups

### 🎨 Modern UI
- **Beautiful Dark Theme**: Stunning visual design with customtkinter
- **Real-time Dashboard**: Live statistics and threat monitoring
- **Interactive Controls**: Easy-to-use permission management
- **CLI Mode**: Full functionality without GUI for servers

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/LockOn.git
cd LockOn

# Run setup to install dependencies
python setup.py install --extras

# Verify the environment
python setup.py doctor
```

The `--extras` flag installs additional features listed in
`requirements-optional.txt`.

Network monitoring relies on the `psutil` package. If it isn't
available, Lock On uses a simplified built-in stub so the monitor can
still run, albeit with reduced information.

For full malware detection capabilities you also need the
`yara-python` package which is included in `requirements.txt`.
If you installed dependencies manually make sure to run:

```bash
pip install yara-python>=4.3.0
pip install pefile>=2023.2.7  # for signed executable detection
```

On Windows, compile `native/privileges.cpp` into `privileges.dll` to enable
service hardening:

```cmd
cl /LD native\privileges.cpp /Fe:native\privileges.dll
```
The DLL is loaded automatically at startup and used to elevate and verify
required privileges for critical actions.

### Basic Usage

```bash
# GUI Mode (default)
python main.py

# CLI Mode (automatic on headless systems)
python main.py
```

## 📸 Screenshots

### Dashboard View
![Dashboard](assets/screenshots/dashboard.png)
*Real-time security overview with threat statistics*

### Monitor View
![Monitor](assets/screenshots/monitor.png)
*Live file system activity monitoring*

### Permissions Management
![Permissions](assets/screenshots/permissions.png)
*Configure security rules and access policies*

## 🔧 Configuration

The configuration file `config.yaml` controls runtime settings. By default the
database file is stored at `data/database.db`. Edit this value under the
`database.path` key if you want to log to a different location. The generated
database is ignored by Git, so you can freely experiment without polluting the
repository. The same section contains a `logging` block where you can specify
the log file path and log level used by the command-line tools and debugger.
Set the `LOCKON_CONFIG` environment variable to load a different configuration
file without passing `--config` each time.

### Security Levels

1. **Passive** 👁️
   - Monitor and log only
   - No automatic actions
   - Suitable for analysis

2. **Active** 🛡️
   - Block suspicious activities
   - Quarantine threats
   - Balanced protection

3. **Aggressive** ⚔️
   - Terminate threats immediately
   - Strict enforcement
   - Maximum security

4. **Paranoid** 💀
   - Nuclear response to threats
   - May affect system usability
   - For critical environments

### Intelligence Patterns

Lock On uses a comprehensive pattern database to detect:
- 🦠 Known malware signatures
- 🔐 Ransomware encryption behaviors
- 🐴 Trojan-like activities
- ⛏️ Cryptocurrency miners
- 📤 Data exfiltration attempts

## 🛠️ Advanced Features

### Quarantine System
- Encrypted isolation of threats
- Metadata preservation
- Secure restoration options
- Forensic analysis support

### File Integrity
- Multiple hash algorithms (MD5, SHA1, SHA256, SHA512)
- Baseline creation and verification
- Tampering detection
- Automated integrity checks

### Active Shield
- Process protection
- Anti-debugging measures
- Network filtering
- Memory protection

## 📚 Documentation

### CLI Commands

```bash
# Lock on to a folder
LockOn> lock /path/to/folder

# Check status
LockOn> status

# Toggle shield
LockOn> shield

# View threats
LockOn> threats

# Manage permissions
LockOn> permissions
```

### API Usage

```python
from core.monitor import FolderMonitor

# Initialize and use as a context manager so monitoring
# stops automatically when the block exits
with FolderMonitor() as monitor:
    monitor.set_target_folder("/important/data")
    monitor.on_threat_detected = handle_threat
    monitor.on_file_changed = handle_change
    monitor.start()
    ...  # application logic
```

## 🔒 Security Features

### Threat Detection
- Pattern matching with regular expressions
- YARA rule scanning with built-in signatures
- Detection of EICAR test files and malicious Office macros
- Detection of base64-encoded command payloads
- Detection of reverse shell commands and malicious downloads
- Detection of certutil and rundll32 download commands
- Detection of Invoke-Obfuscation and Empire frameworks
- Detection of PsExec lateral movement and MSBuild abuse
   - Detection of InstallUtil persistence mechanisms
   - Detection of shellcode loaders using VirtualAllocEx and WriteProcessMemory
   - Detection of process hollowing API sequences
   - Detection of RAT families such as njRAT, DarkComet, and AgentTesla
   - Detection of UPX-packed executables
   - Detection of unsigned executables on Windows
   - Detection of embedded IP addresses with ports
   - Detection of malicious content inside archives
- Process command-line scanning for malicious patterns
- Detection of suspicious environment variables in running processes
- Environment variable analysis is handled by the Intelligence Engine so new patterns automatically apply
- Detection of meterpreter and Cobalt Strike artifacts
- Detection of netsh-based tunneling commands
- Detection of webhook URLs used for data exfiltration
- Detection of AutoIt compiled scripts
- Detection of keylogger APIs
- Detection of Discord token-stealer behavior
- Heuristic analysis
- Entropy calculation
- Behavioral anomaly detection
- Windows service hardening via privilege elevation and verification
- Automatic privilege elevation at startup when the optional native helper is
  available
- Unified `PrivilegeManager` acquires and verifies required privileges on startup
- Network monitor requests debug rights on Windows for accurate connection logging
- Decorator `require_privileges` ensures sensitive functions obtain rights and raises `PermissionError` when privileges are missing
- Privileges are re-verified during monitoring loops to prevent privilege loss
- Background privilege monitor periodically reacquires dropped rights
- Cross-platform `is_elevated()` helper detects administrative privileges
- Rich threat summaries highlight YARA matches within snippets for clear logs

### Response Actions
- File quarantine with encryption
- Process suspension/termination
- Network connection blocking
- Emergency backup creation
- System lockdown

### Harsh Punishments
- CPU throttling for malicious processes
- Memory restriction
- Complete network isolation
- Permission stripping
- Forensic evidence collection

## 📊 Performance

- **Low CPU Usage**: < 5% during normal monitoring
- **Memory Efficient**: ~50-100MB RAM usage
- **Fast Scanning**: 1000+ files/second
- **Real-time Response**: < 100ms threat detection

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Debugging in VS Code

The repository includes a `.vscode/launch.json` configuration. Open the folder
in Visual Studio Code and run the **Run LockOn** launch target to start the
application under the debugger.

Import resolution in VS Code relies on the `.env` file in the repository
root which sets `PYTHONPATH=./src`. The Python extension picks this up
automatically so Pylance recognizes modules like `core` and `security`.
If you relocate the env file be sure to update your `python.envFile`
setting accordingly.

To debug inside the Vagrant VM simply run the helper script:

```bash
scripts/debug_vm.sh
```
This script boots the VM and ensures the `lockon-debug` service is running.
If Vagrant is not installed the script automatically falls back to Docker if it
is available. When neither is present the debug server runs locally so you can
still attach a debugger.
When running locally the helper installs `debugpy` automatically if it is not
already available. The process ID is stored in `data/local_debug.pid` so you can
stop the server later using the `halt` command. `debugpy` is required for remote
debugging regardless of whether you use Vagrant, Docker or the local fallback.
You can verify the environment anytime with:

```bash
python scripts/manage_vm.py doctor
```

Under the hood it calls a Python environment manager that automatically selects
the best available backend (Vagrant preferred, then Docker, otherwise local):

```bash
python scripts/manage_vm.py start --open-vscode
python setup.py vm start --open-vscode
```

`manage_vm.py` dynamically selects a **Vagrant**, **Docker**, or **local**
backend using an internal `EnvironmentManager` so the same commands work in any
environment.
After starting, run:

```bash
python scripts/manage_vm.py doctor
```
to verify that the debug server is running and `debugpy` is installed.

The helper also supports additional subcommands regardless of whether it is controlling Vagrant or Docker:

```bash
python scripts/manage_vm.py status
python scripts/manage_vm.py halt
python scripts/manage_vm.py ssh
python scripts/manage_vm.py logs
python scripts/manage_vm.py doctor
python setup.py vm doctor
```

The `doctor` command checks that the chosen backend has `debugpy` installed and
the debug server running. For Docker it executes a quick check inside the
`lockon` container, while the local backend verifies the background process via
`data/local_debug.pid`.

Use `--provision` with `start` to reprovision the VM. Once running, attach your
debugger using the **Attach to VM** configuration in VS Code. The debug port
defaults to **5678** but can be changed by setting the `LOCKON_DEBUG_PORT`
environment variable or the `--port` flag when starting the environment.
Pass `--open-vscode` to `manage_vm.py` or `debug_vm.sh` to automatically launch
Visual Studio Code with the correct environment configured.

### Running inside Docker

If you do not want to install Vagrant you can spin up a lightweight Docker
container instead. A `Dockerfile` and `docker-compose.yml` are provided. Simply
execute:

```bash
scripts/debug_docker.sh
```

This builds the image, starts the container and exposes the debug port (default
**5678**). Set `LOCKON_DEBUG_PORT` before running the script if you need to use
a different port. Attach VS Code using the **Attach to VM** configuration to
begin debugging the code running inside Docker.

### Development Container

If you are using Visual Studio Code with the **Dev Containers** extension you
can launch a fully configured environment without installing Vagrant or Docker
manually. Open the project in VS Code and choose **Reopen in Container**. The
provided `.devcontainer` folder builds a minimal image with all dependencies and
forwards port **5678** so the debugger can attach automatically.

Once the container starts the workspace is mounted and you can run the
application or attach using the **Attach to VM** launch configuration. The
debug server is started automatically on container boot so VS Code can
immediately attach on the forwarded port. The debug port can be customized
by setting `LOCKON_DEBUG_PORT` in the container environment.

### Command-line Mode

For headless environments you can run the monitoring engine directly without
the UI:

```bash
python -m core.monitor_cli run
```

Pass `--debug` to wait for a debugger connection (use `--debug-port` or
`LOCKON_DEBUG_PORT` to change the port) before monitoring starts:

```bash
python -m core.monitor_cli run --debug
```

The CLI reads `config.yaml` just like the GUI and logs events to the database
specified there. You can override settings on the command line:

```bash
python -m core.monitor_cli run --folder /tmp --db /tmp/events.db
```

Use `--config myconfig.yaml` to load an alternative configuration file.

To inspect logged information without starting monitoring, use the subcommands
`events` and `threats`:

```bash
python -m core.monitor_cli events --limit 5
python -m core.monitor_cli threats --limit 5
```
To save logs for offline analysis, use the `export` command which writes CSV files:

```bash
python -m core.monitor_cli export events events.csv
python -m core.monitor_cli export threats threats.csv
```
To view the monitored file tree for a folder without starting the UI:

```bash
python -m core.monitor_cli tree -f /path/to/folder
```

Watchlist paths are persisted in the database and can be managed directly:

```bash
python -m core.monitor_cli watch add /tmp/suspicious.exe
python -m core.monitor_cli watch list
python -m core.monitor_cli watch scan
```
Show database statistics like logged events and threats:

```bash
python -m core.monitor_cli stats --db data/database.db
```
This prints the total events, threats, watchlist entries and stored file hashes.

### Running inside Vagrant

If you prefer to test in an isolated VM, a `Vagrantfile` is provided. Install
[Vagrant](https://www.vagrantup.com/) and run:

```bash
vagrant up
vagrant ssh
cd /vagrant
python3 main.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

Lock On is a powerful security tool. Use responsibly and ensure you have proper authorization before monitoring any folders. The developers are not responsible for any misuse of this software.

## 🙏 Acknowledgments

- CustomTkinter for the beautiful UI framework
- YARA for malware detection capabilities
- The security research community

## 📞 Support

- 📧 Email: support@lockon.security
- 💬 Discord: [Join our server](https://discord.gg/lockon)
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/LockOn/issues)

---

**Lock On** - *Your files' guardian angel with an attitude* 🔒✨
