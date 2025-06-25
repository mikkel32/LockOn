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

# Run setup
python setup.py

# Install dependencies
pip install -r requirements.txt
```

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
