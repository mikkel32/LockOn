# 🔒 Lock On - Intelligent Folder Security System

![Lock On Banner](assets/banner.png)

Lock On is an advanced folder security monitoring system that uses intelligent pattern analysis to protect your files from malicious activities. With real-time monitoring, AI-powered threat detection, and aggressive countermeasures, Lock On ensures your data stays safe.

## ✨ Features

### 🛡️ Advanced Protection
- **Real-time Monitoring**: Continuously watches folder activities for suspicious behavior
- **AI Pattern Recognition**: Intelligent analysis of file operations and process behaviors
- **Multi-layered Security**: File scanning, process monitoring, and network protection
- **Honeypot System**: Deploy decoy files to catch malicious actors

### 🧠 Intelligence Engine
- **Pattern-based Detection**: Recognizes ransomware, trojans, and other malware patterns
- **Behavioral Analysis**: Identifies suspicious activities based on behavior patterns
- **Machine Learning**: Adaptive threat detection that learns from events
- **YARA Integration**: Professional malware detection rules

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
from core.intelligence import IntelligenceEngine

# Initialize monitor
monitor = FolderMonitor()
monitor.set_target_folder("/important/data")

# Set callbacks
monitor.on_threat_detected = handle_threat
monitor.on_file_changed = handle_change

# Start monitoring
monitor.start()
```

## 🔒 Security Features

### Threat Detection
- Pattern matching with regular expressions
- YARA rule scanning
- Heuristic analysis
- Entropy calculation
- Behavioral anomaly detection

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

Under the hood it calls a Python environment manager that automatically selects
the best available backend (Vagrant preferred, then Docker, otherwise local):

```bash
python scripts/manage_vm.py start
```

`manage_vm.py` dynamically selects a **Vagrant**, **Docker**, or **local**
backend using an internal `EnvironmentManager` so the same commands work in any
environment.

The helper also supports additional subcommands regardless of whether it is controlling Vagrant or Docker:

```bash
python scripts/manage_vm.py status
python scripts/manage_vm.py halt
python scripts/manage_vm.py ssh
python scripts/manage_vm.py logs
python scripts/manage_vm.py doctor
```

The `doctor` command checks that the chosen backend has `debugpy` installed and
the debug server running. For Docker it executes a quick check inside the
`lockon` container, while the local backend verifies the background process via
`data/local_debug.pid`.

Use `--provision` with `start` to reprovision the VM. Once running, attach your
debugger using the **Attach to VM** configuration in VS Code. The debug port
defaults to **5678** but can be changed by setting the `LOCKON_DEBUG_PORT`
environment variable or the `--port` flag when starting the environment.

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
