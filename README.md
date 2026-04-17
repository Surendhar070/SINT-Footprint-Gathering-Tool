# OSINT Footprint Gathering Tool

A modern, comprehensive GUI-based OSINT (Open Source Intelligence) tool for Windows that enables security professionals and researchers to gather intelligence on various entities including domains, IPs, emails, mobile numbers, persons, organizations, and threat indicators.

## 🌟 Features

- **Modern GUI Interface**: Clean, intuitive Windows desktop application
- **Multi-Entity Support**: Analyze mobile numbers, domains, URLs, emails, IPs, persons, organizations, and threat intelligence
- **Comprehensive Footprinting**: Multiple methods for gathering intelligence on each entity type
- **Auto-Detection**: Automatically detects entity type from input
- **Relationship Graph**: Visualize connections and relationships between entities
- **JSON Export**: Export results in JSON format
- **Report Generation**: Generate formatted text reports
- **Analysis History**: Track previous analyses

## 📋 Supported Entity Types

### 📱 Mobile Number
- Country code detection
- Number format analysis
- Phone lookup capabilities
- International format variations

### 🌐 Domain
- DNS Records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- WHOIS Data (full registrant details)
- Subdomain Enumeration
- SSL/TLS Certificates
- Hosting Provider Detection (AWS, Azure, Cloudflare, etc.)
- CMS Detection (WordPress, Joomla, Drupal, Shopify)
- Technology Stack Detection
- HTTP Headers Analysis

### 🔗 URL
- HTTP headers analysis with security header extraction
- Page content analysis (title, meta tags, description)
- Technology stack detection
- DNS resolution
- SSL/TLS information
- Robots.txt and sitemap analysis
- Security headers (X-Frame-Options, CSP, HSTS, etc.)

### 📧 Email
- Domain Analysis (full domain intelligence)
- MX Records (mail server lookup and priority)
- SPF/DKIM/DMARC (email security records)
- Email Format Analysis
- Disposable Email Detection
- Role-based Detection (admin, support, noreply)
- Gravatar Profiles
- Email Validation

### 🌍 IP Address
- Geolocation (country, region, city, coordinates)
- ASN Information
- ISP Details
- Reverse DNS
- Shared Hosting Analysis
- Netblock Calculation
- Port Scanning (common ports)
- Threat Intelligence (placeholder for API integration)

### 👤 Person / Username
- Social Media Discovery (Twitter, Facebook, LinkedIn, Instagram, GitHub, etc.)
- GitHub Profile Analysis
- Username Enumeration
- Email Pattern Generation
- Forum and Blog Discovery

### 🏢 Organization / Company
- Domain Discovery
- Email Pattern Analysis
- Subsidiary Discovery
- Infrastructure Mapping
- Digital Footprint Analysis

### 🛡️ Threat Intelligence / IOC
- Indicator Detection (IP, Domain, URL, Hash)
- Malicious Domain Check
- Malicious IP Check
- Phishing Infrastructure Detection
- Malware Indicators
- IOC Classification

## 🚀 Installation

### Option 1: Install from Source

1. **Clone or download the repository**
   ```bash
   git clone <repository-url>
   cd OSINT
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python gui_app.py
   ```

### Option 2: Windows Installer

1. Download the installer from the releases page
2. Run `OSINTTool_Setup_v1.0.0.exe`
3. Follow the installation wizard
4. Launch from Start Menu or Desktop shortcut

### Building the Installer (Developers)

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install pyinstaller
   ```

2. **Run the build script**
   ```bash
   build_installer.bat
   ```

3. **Create installer with Inno Setup**
   - Download and install [Inno Setup](https://jrsoftware.org/isdl.php)
   - Open `installer_builder.iss` in Inno Setup Compiler
   - Click "Build" → "Compile"
   - The installer will be created in the `installer` folder

## 📖 Usage

1. **Launch the Application**
   - Double-click the OSINT Tool shortcut or run `OSINTTool.exe`

2. **Analyze an Entity**
   - Enter the entity in the input field (domain, IP, email, etc.)
   - Click "Analyze" or press Enter
   - Wait for the analysis to complete

3. **View Results**
   - Results are displayed in the "Results" tab
   - Switch to "Relationship Graph" tab to see visual connections
   - Check "History" tab for previous analyses

4. **Export Data**
   - Click "Export JSON" to save results as JSON
   - Click "Export Report" to save a formatted text report
   - Click "Save Graph" in the graph tab to export the relationship graph

## 🛠️ Requirements

- Windows 10 or later (64-bit)
- Python 3.8+ (if running from source)
- Internet connection (for API lookups and DNS queries)

### Python Dependencies
- `requests` - HTTP library
- `dnspython` - DNS toolkit
- `python-whois` - WHOIS queries
- `phonenumbers` - Phone number parsing
- `matplotlib` - Graph visualization
- `networkx` - Network graph library

## 📁 Project Structure

```
OSINT/
├── osint_tool/              
│   ├── core/
│   │   ├── domain_analyzer.py
│   │   ├── email_analyzer.py
│   │   ├── ip_analyzer.py
│   │   ├── url_analyzer.py
│   │   ├── mobile_analyzer.py
│   │   ├── person_analyzer.py
│   │   ├── organization_analyzer.py
│   │   ├── ioc_analyzer.py
│   │   ├── entity_detector.py
│   │   └── relationship_analyzer.py
├── gui_app.py               # Main GUI application
├── main.py                  # Entry point
├── requirements.txt         # Python dependencies
├── build_installer.bat      # Build script
├── installer_builder.iss    # Inno Setup script
└── README.md               # This file
```

## ⚠️ Important Notes

- **API Integrations**: Some features (threat intelligence checks, social media verification) require API keys. These are placeholders and need integration with respective services.
- **Rate Limits**: Be mindful of rate limits when performing multiple analyses. Some services may throttle requests.
- **Legal Use**: This tool is for legitimate security research and authorized testing only. Ensure you have proper authorization before analyzing any entities.
- **Privacy**: Respect privacy laws and regulations when using this tool.

## 🔧 Troubleshooting

### Application won't start
- Ensure you have the latest Windows updates
- Check that all dependencies are installed correctly
- Try running from command line to see error messages

### Graph visualization not working
- Install matplotlib and networkx: `pip install matplotlib networkx`
- Ensure you have analyzed at least one entity

### DNS queries failing
- Check your internet connection
- Verify DNS settings
- Some DNS queries may be blocked by firewalls


## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues, questions, or suggestions, please open an issue on the GitHub repository.

## 🙏 Acknowledgments

Built with:
- Python
- Tkinter (GUI)
- Matplotlib & NetworkX (Graph visualization)
- PyInstaller (Packaging)
- Inno Setup (Installer)
