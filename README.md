# 🔍 Elbanna Recon v1.0

**Professional Cybersecurity Reconnaissance Toolkit**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.md)
[![Educational](https://img.shields.io/badge/purpose-Educational%20%7C%20Ethical%20Hacking-red.svg)](README.md)

---

## 🎯 Overview

**Elbanna Recon v1.0** is a comprehensive cybersecurity reconnaissance toolkit designed for **educational purposes** and **ethical hacking** scenarios. This modular CLI application provides a wide range of information gathering and security analysis tools in a professional, easy-to-use interface.

**Author:** Yousef Osama (@YousefE1bana)  
**University:** Egyptian Chinese University - Cybersecurity Engineering  
**Contact:** y3usef.osama@gmail.com  
**LinkedIn:** [www.linkedin.com/in/yousefelbana](https://www.linkedin.com/in/yousefelbana)  
**GitHub:** [github.com/YousefE1bana](https://github.com/YousefE1bana)  
**Version:** 1.0  
**Last Updated:** September 9, 2025

---

## ⚠️ **IMPORTANT LEGAL DISCLAIMER**

This tool is intended for **EDUCATIONAL PURPOSES ONLY** and **AUTHORIZED SECURITY TESTING**. 

- ✅ **DO USE** for learning cybersecurity concepts
- ✅ **DO USE** for authorized penetration testing
- ✅ **DO USE** for security research on your own systems
- ❌ **DO NOT USE** for unauthorized access to systems
- ❌ **DO NOT USE** for malicious activities
- ❌ **DO NOT USE** against systems you don't own or have explicit permission to test

**The author is not responsible for any misuse of this tool. Users are solely responsible for ensuring their activities comply with applicable laws and regulations.**

---

## 🚀 Features

### 🌐 Network Reconnaissance
- **Port Scanner**: Advanced TCP/UDP port scanning with service detection
- **Packet Sniffer**: Real-time network traffic analysis and monitoring
- **Subdomain Scanner**: Comprehensive subdomain enumeration and discovery

### 🔍 Information Gathering
- **WHOIS Lookup**: Domain registration and ownership information
- **DNS Lookup**: Comprehensive DNS record analysis (A, AAAA, MX, NS, TXT, etc.)
- **IP Lookup**: Geolocation and ISP information for IP addresses
- **Website Age**: Historical website information and creation dates
- **Header Info**: HTTP header analysis and security assessment

### 🔐 Security Analysis
- **Password Cracker**: Hash cracking using dictionary attacks (MD5, SHA1, SHA256, SHA512)
- **Steganography Tool**: Hidden data detection and analysis in images
- **URL Scanner**: URL safety analysis and reputation checking
- **EXIF Metadata**: Image metadata extraction and analysis

### 🕵️ Advanced Tools
- **Git Reconnaissance**: GitHub user and repository analysis
- **YouTube Lookup**: Video and channel information gathering
- **URL Expander**: Short URL expansion and redirect chain analysis
- **User-Agent Lookup**: Browser and device fingerprinting analysis

### 📊 Reporting & Utilities
- **Multi-Format Reports**: Save results in JSON, TXT, HTML, and CSV formats
- **Session Tracking**: Track and log all reconnaissance activities
- **Colorized Output**: Enhanced terminal experience with colored results
- **Configuration Management**: YAML-based configuration for all tools

---

## 📋 System Requirements

### Python Version
- **Python 3.8+** (Recommended: Python 3.11 or newer)

### Operating Systems
- ✅ **Windows 10/11** (PowerShell support)
- ✅ **Linux** (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- ✅ **macOS** (macOS 11+)

### Network Requirements
- Internet connection for online lookups and API calls
- Administrator/root privileges for packet sniffing operations

---

## 🛠️ Installation

### 🐧 Linux/macOS Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YousefE1bana/elbanna-recon.git
   cd elbanna-recon
   ```

2. **Run the automatic setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Activate the virtual environment:**
   ```bash
   source venv/bin/activate
   ```

4. **Run the tool:**
   ```bash
   python elbanna_recon.py
   ```

### 🪟 Windows Installation

1. **Clone or download the repository**

2. **Run the setup script:**
   ```powershell
   setup.bat
   ```

3. **Activate the virtual environment:**
   ```powershell
   venv\Scripts\activate
   ```

4. **Run the tool:**
   ```powershell
   python elbanna_recon.py
   ```

### 📦 Manual Installation

If you prefer manual installation:

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Run the tool
python elbanna_recon.py
```

---

## 🎮 Usage

### Basic Usage

1. **Start the application:**
   ```bash
   python elbanna_recon.py
   ```

2. **Navigate the menu using numbers (1-20)**

3. **Follow the prompts for each tool**

4. **View results in colorized terminal output**

5. **Save results using the Reports module**

### Example Workflows

#### 🔍 **Basic Domain Reconnaissance**
```
1. WHOIS Lookup → Enter domain
2. DNS Lookup → Enter same domain
3. Subdomain Scanner → Discover subdomains
4. Reports → Save all results
```

#### 🌐 **Network Analysis**
```
1. Port Scanner → Scan target IP/domain
2. Packet Sniffer → Monitor network traffic
3. IP Lookup → Get geolocation info
4. Reports → Document findings
```

#### 🔐 **Security Assessment**
```
1. Header Info → Analyze HTTP headers
2. URL Scanner → Check URL safety
3. EXIF Metadata → Analyze image files
4. Steganography Tool → Check for hidden data
```

### Configuration

Edit `config.yaml` to customize:
- Default settings for each tool
- API keys for external services
- Logging preferences
- Output formats
- Security settings

---

## 📊 Sample Output

### Port Scanner Results
```
🚀 ELBANNA RECON v1.0 - PORT SCANNER
================================================
Target: example.com
Scanning ports: [80, 443, 22, 21, 25]

✅ Port 80 (HTTP) - OPEN
✅ Port 443 (HTTPS) - OPEN
❌ Port 22 (SSH) - CLOSED
❌ Port 21 (FTP) - CLOSED
❌ Port 25 (SMTP) - CLOSED

📊 Summary: 2/5 ports open
⏱️ Scan completed in 3.45 seconds
```

### WHOIS Lookup Results
```
🔍 WHOIS LOOKUP RESULTS
================================================
Domain: example.com
Registrar: Example Registrar Inc.
Creation Date: 1995-08-14
Expiration Date: 2025-08-13
Name Servers: ns1.example.com, ns2.example.com
Status: clientTransferProhibited
```

---

## 🔧 Advanced Configuration

### API Keys Setup

Some features require API keys. Add them to `config.yaml`:

```yaml
api_keys:
  virustotal: "your_virustotal_api_key"
  github: "your_github_token"
  shodan: "your_shodan_api_key"
```

### Custom Wordlists

Place custom wordlists in the `wordlists/` directory:
- `subdomains.txt` - For subdomain scanning
- `passwords.txt` - For password cracking
- `directories.txt` - For directory enumeration

### Logging Configuration

Customize logging in `config.yaml`:

```yaml
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR
  file: "logs/elbanna_{date}.log"
  max_size_mb: 10
  backup_count: 5
```

---

## 🧪 Testing

### Run Smoke Tests
```bash
# Using pytest
pytest tests/test_modules_smoke.py -v

# Manual testing
python tests/test_modules_smoke.py
```

### Run Individual Module Tests
```bash
# Test specific functionality
python -m modules.port_scanner
python -m modules.whois_lookup
python -m modules.dns_lookup
```

---

## 📁 Project Structure

```
Elbanna_Recon_v1.0/
├── 📄 elbanna_recon.py          # Main CLI application
├── 📄 config.yaml               # Configuration file
├── 📄 requirements.txt          # Python dependencies
├── 📄 setup.sh                  # Linux/macOS setup script
├── 📄 setup.bat                 # Windows setup script
├── 📄 README.md                 # This file
├── 📄 LICENSE                   # MIT License
├── 📁 modules/                  # Core modules
│   ├── 📄 __init__.py
│   ├── 📄 port_scanner.py       # Port scanning functionality
│   ├── 📄 packet_sniffer.py     # Network traffic analysis
│   ├── 📄 password_cracker.py   # Hash cracking tools
│   ├── 📄 steganography_tool.py # Hidden data detection
│   ├── 📄 whois_lookup.py       # Domain information
│   ├── 📄 dns_lookup.py         # DNS record analysis
│   ├── 📄 subdomain.py          # Subdomain enumeration
│   ├── 📄 ip_lookup.py          # IP geolocation
│   ├── 📄 website_age.py        # Website history
│   ├── 📄 url_scanner.py        # URL safety analysis
│   ├── 📄 header_info.py        # HTTP header analysis
│   ├── 📄 exif_metadata.py      # Image metadata extraction
│   ├── 📄 user_agent_lookup.py  # Browser fingerprinting
│   ├── 📄 git_recon.py          # GitHub reconnaissance
│   ├── 📄 url_expander.py       # URL expansion
│   ├── 📄 youtube_lookup.py     # YouTube analysis
│   └── 📄 reports.py            # Result saving
├── 📁 logs/                     # Application logs
│   └── 📄 elbanna_2025-09-08.log
├── 📁 reports/                  # Saved results
│   └── 📄 results.json
├── 📁 tests/                    # Test suites
│   └── 📄 test_modules_smoke.py
└── 📁 wordlists/               # Custom wordlists (optional)
    ├── 📄 subdomains.txt
    ├── 📄 passwords.txt
    └── 📄 directories.txt
```

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Follow coding standards** (see `Y.instructions.md`)
4. **Add tests** for new functionality
5. **Commit changes** (`git commit -m 'Add amazing feature'`)
6. **Push to branch** (`git push origin feature/amazing-feature`)
7. **Open a Pull Request**

### Development Guidelines
- Follow PEP 8 for Python code style
- Add docstrings to all functions and classes
- Include error handling for all external operations
- Test thoroughly before submitting

---

## 🐛 Troubleshooting

### Common Issues

#### **Permission Denied (Packet Sniffer)**
```bash
# Linux/macOS: Run with sudo
sudo python elbanna_recon.py

# Windows: Run PowerShell as Administrator
```

#### **Module Import Errors**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

#### **Network Connectivity Issues**
- Check internet connection
- Verify firewall settings
- Ensure DNS resolution is working

#### **API Rate Limiting**
- Some tools may hit API rate limits
- Add delays between requests
- Use API keys for higher limits

### Getting Help

1. **Check the logs** in `logs/` directory
2. **Run smoke tests** to verify installation
3. **Check configuration** in `config.yaml`
4. **Open an issue** on GitHub with:
   - Error message
   - Operating system
   - Python version
   - Steps to reproduce

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### MIT License Summary
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use
- ❌ Liability
- ❌ Warranty

---

## 🙏 Acknowledgments

- **Python Community** for excellent libraries
- **Cybersecurity Community** for tools and techniques
- **Egyptian Chinese University** for educational support
- **Open Source Contributors** who made this possible

### Libraries Used
- `requests` - HTTP operations
- `scapy` - Packet manipulation
- `dnspython` - DNS operations
- `python-whois` - WHOIS lookups
- `exifread` - EXIF data extraction
- `pillow` - Image processing
- `colorama` - Terminal colors
- `pyfiglet` - ASCII art
- `user-agents` - User agent parsing

---

## 📞 Contact & Support

- **Author:** Yousef Osama
- **Institution:** Egyptian Chinese University - Cybersecurity Engineering
- **Email:** (y3usef.osama@gmail.com)
- **GitHub:** (https://github.com/YousefE1bana)

### Educational Purpose Statement

This tool was developed as part of cybersecurity education and training. It demonstrates various reconnaissance techniques used in ethical hacking and penetration testing. All techniques implemented are well-documented and publicly available.

---

## 🔮 Future Enhancements

### Planned Features
- 🌐 **Web Interface** - Browser-based GUI
- 🤖 **AI-Powered Analysis** - Automated vulnerability assessment
- 📱 **Mobile Support** - Android/iOS companion app
- 🔄 **API Integration** - RESTful API for automation
- 📊 **Advanced Reporting** - PDF reports with charts
- 🛡️ **Security Modules** - Additional security analysis tools

### Contribution Opportunities
- New reconnaissance modules
- Enhanced error handling
- Performance optimizations
- Documentation improvements
- Test coverage expansion

---

## ⭐ Star History

If you find this tool useful, please consider giving it a star on GitHub! ⭐

Your support helps us continue developing and improving this educational cybersecurity toolkit.

---

## 👨‍💻 **About the Author**

**Yousef Osama** is a Cybersecurity Engineering student at Egyptian Chinese University, passionate about ethical hacking, penetration testing, and cybersecurity education. This project represents his commitment to making cybersecurity knowledge more accessible to students and professionals worldwide.

### Connect with me:
- 🎓 **University:** Egyptian Chinese University - Cybersecurity Engineering
- 💼 **LinkedIn:** [www.linkedin.com/in/yousefelbana](https://www.linkedin.com/in/yousefelbana)
- 🐙 **GitHub:** [github.com/YousefE1bana](https://github.com/YousefE1bana)
- 📧 **Email:** y3usef.osama@gmail.com

### Interests:
- 🛡️ Ethical Hacking & Penetration Testing
- 🔍 Digital Forensics & Incident Response
- 🌐 Network Security & Analysis
- 🎓 Cybersecurity Education & Training
- 🛠️ Security Tool Development

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally!** 🛡️

---

*Last updated: September 8, 2025*
