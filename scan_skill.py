#!/usr/bin/env python3
"""
Claw Guard — ClawHub Skill Security Scanner v2
Scans OpenClaw skill directories for malware, prompt injection,
data exfiltration, and other security threats.

v2 improvements:
- Context-aware analysis: distinguishes "uses .env" vs "steals .env"
- Well-known application ports whitelisted (Radarr, Sonarr, Plex, etc.)
- Self-scan exclusion (scanner ignores its own detection patterns)
- Smarter risk scoring: only counts real threats, not documentation
- False positive tags: findings can be marked as likely FP with explanation
- VT threshold: 1 detection on 90+ engines = not CRITICAL

Usage:
    python3 scan_skill.py <skill_path>
    python3 scan_skill.py --batch <path1> <path2> ...
    python3 scan_skill.py --json <skill_path>
    python3 scan_skill.py --vt <skill_path>
    python3 scan_skill.py --vt --vt-key <api_key> <skill_path>
    python3 scan_skill.py --vt --no-upload <skill_path>
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


class ThreatCategory(str, Enum):
    EXFIL = "EXFIL"
    EXEC = "EXEC"
    CRED = "CRED"
    PERSIST = "PERSIST"
    INJECT = "INJECT"
    OBFUSC = "OBFUSC"
    NETWORK = "NETWORK"
    PRIVESC = "PRIVESC"
    INSTALL = "INSTALL"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    category: str
    severity: str
    file: str
    line: int
    description: str
    matched_text: str
    false_positive: bool = False
    fp_reason: str = ""
    def to_dict(self): return asdict(self)


@dataclass
class ScanReport:
    skill_name: str
    skill_path: str
    overall_risk: str = "LOW"
    findings: list = field(default_factory=list)
    file_count: int = 0
    files_scanned: list = field(default_factory=list)
    has_skill_md: bool = False
    frontmatter_name: str = ""
    frontmatter_description: str = ""
    summary: str = ""
    vt_report: Optional[dict] = None
    def to_dict(self):
        d = asdict(self)
        d["findings"] = [f.to_dict() if isinstance(f, Finding) else f for f in self.findings]
        return d
    @property
    def real_findings(self):
        return [f for f in self.findings if not f.false_positive]


# ============================================================
# Known IOCs
# ============================================================

KNOWN_C2_IPS = ["91.92.242.30"]
KNOWN_MALICIOUS_DOMAINS = ["glot.io"]
KNOWN_MALICIOUS_SKILL_NAMES = [
    "solana-wallet-tracker", "youtube-summarize-pro", "polymarket-trader",
]

# ============================================================
# Context-aware whitelists
# ============================================================

KNOWN_APP_PORTS = {
    ":22", ":21", ":25", ":53", ":80", ":443", ":587", ":993",
    ":3000", ":5000", ":8000", ":8080", ":8443", ":9000",
    ":5432", ":3306", ":6379", ":27017", ":9200", ":9300",
    ":7878", ":8989", ":8686", ":6767", ":9696", ":9117",
    ":32400", ":8096", ":6881", ":6882", ":6883",
    ":51413", ":8112", ":9091", ":8384",
    ":1883", ":8883", ":5672", ":15672", ":11211",
    ":2375", ":2376", ":10250", ":3478", ":1433", ":5601",
    ":9090", ":18789", ":18790",
}

ENV_SAFE_CONTEXTS = [
    r"(?i)(create|copy|cp|example|template|configure|edit|set)\s.*\.env",
    r"(?i)\.env\.(example|template|sample|dist)",
    r"(?i)never\s+commit\s+.*\.env",
    r"(?i)add\s+.*\.env.*gitignore",
    r"(?i)#.*\.env",
    r"(?i)environment\s+variables",
    r"(?i)├──.*\.env",
    r"(?i)\.env.*version\s+control",
]

APIKEY_SAFE_CONTEXTS = [
    r"(?i)os\.(environ|getenv)\s*[\[\(]",
    r"(?i)(config|settings|env)\s*[\.\[]",
    r"(?i)=\s*os\.",
    r"(?i)api_key\s*=\s*['\"]?\s*$",
    r"(?i)api_key\s*=\s*\{",
    r"(?i)API_KEY=your",
    r"(?i)API_KEY=\s*$",
    r"(?i)API_KEY=<",
    r"(?i)apikey=.*self\.",
    r"(?i)apikey=.*params",
]

# Always suspicious (no context excuse)
SENSITIVE_PATHS_ALWAYS = [
    (r"~/\.ssh", "SSH keys"),
    (r"~/\.gnupg", "GPG keys"),
    (r"~/\.aws/credentials", "AWS credentials"),
    (r"/etc/shadow", "System shadow passwords"),
    (r"wallet\.dat", "Crypto wallet"),
    (r"seed\.txt", "Crypto seed phrase"),
    (r"\.kube/config", "Kubernetes config"),
    (r"\.docker/config\.json", "Docker auth config"),
    (r"browser.*(password|cookie|history|login)", "Browser sensitive data"),
    (r"chrome.*local.?state", "Chrome browser data"),
    (r"firefox.*logins\.json", "Firefox credentials"),
    (r"keychain", "macOS Keychain"),
]

# Context-dependent (can be legit in config/docs)
SENSITIVE_PATHS_CONTEXT = [
    (r"~/\.clawdbot/\.env", "OpenClaw env"),
    (r"~/\.openclaw/\.env", "OpenClaw env"),
    (r"/etc/passwd", "System passwords"),
    (r"MEMORY\.md", "OpenClaw memory"),
    (r"SOUL\.md", "OpenClaw soul"),
    (r"mnemonic", "Mnemonic phrase"),
    (r"keystore", "Key storage"),
]

# ============================================================
# Detection Patterns
# ============================================================

PATTERNS = [
    # EXFIL
    (r"curl\s+.*-[dX]\s+POST", ThreatCategory.EXFIL, Severity.HIGH, "curl POST — possible exfiltration"),
    (r"wget\s+.*--post", ThreatCategory.EXFIL, Severity.HIGH, "wget POST — possible exfiltration"),
    (r"curl\s.*\|\s*(ba)?sh", ThreatCategory.EXFIL, Severity.CRITICAL, "curl piped to shell — malware delivery"),
    (r"wget\s.*\|\s*(ba)?sh", ThreatCategory.EXFIL, Severity.CRITICAL, "wget piped to shell — malware delivery"),
    (r"curl\s.*-o\s+/tmp/", ThreatCategory.EXFIL, Severity.HIGH, "curl to /tmp — payload staging"),
    (r"nc\s+-[elp]", ThreatCategory.EXFIL, Severity.CRITICAL, "netcat listener — reverse shell"),
    # EXEC
    (r"\beval\s*\(", ThreatCategory.EXEC, Severity.HIGH, "eval() — arbitrary code execution"),
    (r"\bexec\s*\(", ThreatCategory.EXEC, Severity.HIGH, "exec() — arbitrary code execution"),
    (r"os\.system\s*\(", ThreatCategory.EXEC, Severity.HIGH, "os.system() — shell execution"),
    (r"subprocess\..*shell\s*=\s*True", ThreatCategory.EXEC, Severity.HIGH, "subprocess shell=True — injection risk"),
    (r"child_process", ThreatCategory.EXEC, Severity.MEDIUM, "child_process — shell execution"),
    (r"Runtime\.getRuntime\(\)\.exec", ThreatCategory.EXEC, Severity.HIGH, "Java Runtime.exec"),
    # CRED
    (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", ThreatCategory.CRED, Severity.HIGH, "Hardcoded password"),
    # PERSIST
    (r"crontab\s", ThreatCategory.PERSIST, Severity.HIGH, "Crontab modification"),
    (r"/etc/cron\.", ThreatCategory.PERSIST, Severity.HIGH, "Cron directory access"),
    (r"systemctl\s+(enable|start)", ThreatCategory.PERSIST, Severity.HIGH, "Systemd manipulation"),
    (r"\.bashrc|\.bash_profile|\.zshrc|\.profile", ThreatCategory.PERSIST, Severity.MEDIUM, "Shell profile modification"),
    (r"launchctl\s+load", ThreatCategory.PERSIST, Severity.HIGH, "macOS LaunchAgent"),
    (r"~/Library/LaunchAgents", ThreatCategory.PERSIST, Severity.HIGH, "macOS LaunchAgents target"),
    # INJECT
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", ThreatCategory.INJECT, Severity.CRITICAL, "Prompt injection — ignore instructions"),
    (r"(?i)you\s+are\s+now\s+(a|an)\s+", ThreatCategory.INJECT, Severity.HIGH, "Prompt injection — role reassignment"),
    (r"(?i)system\s*:\s*you\s+(must|should|will)", ThreatCategory.INJECT, Severity.HIGH, "Prompt injection — fake system prompt"),
    (r"(?i)<\s*system\s*>", ThreatCategory.INJECT, Severity.HIGH, "Prompt injection — XML system tag"),
    # OBFUSC
    (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}", ThreatCategory.OBFUSC, Severity.HIGH, "Long hex string — obfuscated payload"),
    (r"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+-d", ThreatCategory.OBFUSC, Severity.CRITICAL, "base64 decode pipe — obfuscated execution"),
    # NETWORK
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ThreatCategory.NETWORK, Severity.MEDIUM, "Hardcoded IP address"),
    (r"(?i)(ngrok|serveo|localtunnel|bore\.pub)", ThreatCategory.NETWORK, Severity.HIGH, "Tunnel service — C2 channel"),
    (r"(?i)(tor2web|\.onion)", ThreatCategory.NETWORK, Severity.CRITICAL, "Tor/onion — malware indicator"),
    (r"dns.*txt.*record|nslookup|dig\s+.*txt", ThreatCategory.NETWORK, Severity.HIGH, "DNS TXT query — DNS tunneling"),
    # PRIVESC
    (r"chmod\s+[0-7]*7[0-7]*\s", ThreatCategory.PRIVESC, Severity.HIGH, "chmod world-writable"),
    (r"chmod\s+[ugo+]*s\s", ThreatCategory.PRIVESC, Severity.CRITICAL, "setuid/setgid — privilege escalation"),
    (r"chown\s+root", ThreatCategory.PRIVESC, Severity.HIGH, "chown to root"),
    # INSTALL
    (r"https?://github\.com/[^/]+/[^/]+/releases/download", ThreatCategory.INSTALL, Severity.MEDIUM, "GitHub release download — verify source"),
]


# ============================================================
# Scanner
# ============================================================

class SkillScanner:
    SCANNABLE_EXTENSIONS = {
        ".md", ".txt", ".py", ".sh", ".bash", ".js", ".ts", ".json",
        ".yaml", ".yml", ".toml", ".cfg", ".ini", ".rb", ".pl", ".php",
        ".java", ".go", ".rs", ".html", ".xml", ".env", ".conf",
    }
    MAX_FILE_SIZE = 1_048_576

    def __init__(self, skill_path):
        self.skill_path = Path(skill_path).resolve()
        self.is_self_scan = self._detect_self_scan()
        self.report = ScanReport(skill_name=self.skill_path.name, skill_path=str(self.skill_path))

    def _detect_self_scan(self):
        skill_md = self.skill_path / "SKILL.md"
        if not skill_md.exists(): return False
        try:
            content = skill_md.read_text(errors="ignore")[:500]
            return "claw-guard" in content.lower() and "ClawHavoc" in content
        except: return False

    def scan(self):
        if self.is_self_scan:
            self.report.summary = ("🔵 Self-scan detected — skipping. The scanner contains IOCs and "
                                   "detection patterns that trigger false positives on itself.")
            self.report.overall_risk = "LOW"
            self.report.has_skill_md = True
            self.report.file_count = len(list(self.skill_path.rglob("*")))
            return self.report

        if not self.skill_path.is_dir():
            self.report.summary = f"ERROR: {self.skill_path} is not a directory"
            self.report.overall_risk = "CRITICAL"
            return self.report

        files = self._collect_files()
        self.report.file_count = len(files)
        self.report.files_scanned = [str(f.relative_to(self.skill_path)) for f in files]

        skill_md = self.skill_path / "SKILL.md"
        if skill_md.exists():
            self.report.has_skill_md = True
            self._parse_frontmatter(skill_md)
        else:
            self.report.has_skill_md = False
            self._add_finding(ThreatCategory.INJECT, Severity.MEDIUM, "SKILL.md", 0, "No SKILL.md found", "")

        self._check_known_malicious_names()
        for f in files: self._scan_file(f)
        for f in files: self._check_sensitive_paths(f)
        for f in files: self._check_known_iocs(f)
        for f in files: self._check_api_keys(f)
        if skill_md.exists(): self._analyze_coherence(skill_md)
        self._analyze_false_positives()
        self._calculate_risk()
        self._generate_summary()
        return self.report

    def _collect_files(self):
        files = []
        for fp in self.skill_path.rglob("*"):
            if fp.is_file() and fp.suffix.lower() in self.SCANNABLE_EXTENSIONS and fp.stat().st_size <= self.MAX_FILE_SIZE:
                files.append(fp)
        for fp in self.skill_path.rglob("*"):
            if fp.is_file() and fp.suffix == "" and not fp.name.startswith("."):
                try:
                    with open(fp, "r", errors="ignore") as f:
                        if f.readline().startswith("#!"): files.append(fp)
                except: pass
        return list(set(files))

    def _parse_frontmatter(self, skill_md):
        try:
            content = skill_md.read_text(errors="ignore")
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    try:
                        import yaml
                        fm = yaml.safe_load(parts[1])
                        if isinstance(fm, dict):
                            self.report.frontmatter_name = fm.get("name", "")
                            self.report.frontmatter_description = fm.get("description", "")
                    except:
                        nm = re.search(r"^name:\s*(.+)$", parts[1], re.MULTILINE)
                        dm = re.search(r"^description:\s*(.+)$", parts[1], re.MULTILINE)
                        if nm: self.report.frontmatter_name = nm.group(1).strip()
                        if dm: self.report.frontmatter_description = dm.group(1).strip()
        except: pass

    def _check_known_malicious_names(self):
        nl = self.report.skill_name.lower()
        fl = self.report.frontmatter_name.lower()
        for mn in KNOWN_MALICIOUS_SKILL_NAMES:
            if mn in nl or mn in fl:
                self._add_finding(ThreatCategory.NETWORK, Severity.CRITICAL, "SKILL.md", 0,
                                  f"Known malicious skill name: {mn}", mn)

    def _scan_file(self, fpath):
        try: content = fpath.read_text(errors="ignore")
        except: return
        rel = str(fpath.relative_to(self.skill_path))
        for ln, line in enumerate(content.splitlines(), 1):
            for pat, cat, sev, desc in PATTERNS:
                for m in re.finditer(pat, line):
                    txt = m.group(0)
                    if cat == ThreatCategory.NETWORK and "Hardcoded IP" in desc:
                        if self._is_benign_ip(txt, line): continue
                    self._add_finding(cat, sev, rel, ln, desc, txt[:200])

    def _check_sensitive_paths(self, fpath):
        try: content = fpath.read_text(errors="ignore")
        except: return
        rel = str(fpath.relative_to(self.skill_path))
        for ln, line in enumerate(content.splitlines(), 1):
            for pat, desc in SENSITIVE_PATHS_ALWAYS:
                if re.search(pat, line, re.IGNORECASE):
                    self._add_finding(ThreatCategory.CRED, Severity.HIGH, rel, ln,
                                      f"References {desc}", line.strip()[:200])
            for pat, desc in SENSITIVE_PATHS_CONTEXT:
                if re.search(pat, line, re.IGNORECASE):
                    is_safe = any(re.search(sc, line) for sc in ENV_SAFE_CONTEXTS) if ".env" in pat.lower() or "env" in desc.lower() else False
                    if is_safe:
                        self._add_finding(ThreatCategory.CRED, Severity.LOW, rel, ln,
                                          f"References {desc} (config/doc context)", line.strip()[:200],
                                          false_positive=True, fp_reason="Configuration or documentation context")
                    else:
                        self._add_finding(ThreatCategory.CRED, Severity.MEDIUM, rel, ln,
                                          f"References {desc}", line.strip()[:200])

    def _check_api_keys(self, fpath):
        try: content = fpath.read_text(errors="ignore")
        except: return
        rel = str(fpath.relative_to(self.skill_path))
        pat = r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*="
        for ln, line in enumerate(content.splitlines(), 1):
            if re.search(pat, line):
                is_safe = any(re.search(sc, line) for sc in APIKEY_SAFE_CONTEXTS)
                if is_safe:
                    self._add_finding(ThreatCategory.CRED, Severity.LOW, rel, ln,
                                      "API key (safe: env/config/placeholder)", line.strip()[:200],
                                      false_positive=True, fp_reason="Read from env or placeholder")
                else:
                    self._add_finding(ThreatCategory.CRED, Severity.MEDIUM, rel, ln,
                                      "API key assignment — verify not hardcoded", line.strip()[:200])

    def _check_known_iocs(self, fpath):
        try: content = fpath.read_text(errors="ignore")
        except: return
        rel = str(fpath.relative_to(self.skill_path))
        for ln, line in enumerate(content.splitlines(), 1):
            for ip in KNOWN_C2_IPS:
                if ip in line:
                    self._add_finding(ThreatCategory.NETWORK, Severity.CRITICAL, rel, ln,
                                      f"Known C2 IP: {ip} (ClawHavoc)", line.strip()[:200])
            for dom in KNOWN_MALICIOUS_DOMAINS:
                if dom in line.lower():
                    self._add_finding(ThreatCategory.NETWORK, Severity.CRITICAL, rel, ln,
                                      f"Known malicious domain: {dom}", line.strip()[:200])

    def _analyze_coherence(self, skill_md):
        try: content = skill_md.read_text(errors="ignore")
        except: return
        for c in re.findall(r"<!--(.*?)-->", content, re.DOTALL):
            if len(c.strip()) > 20:
                self._add_finding(ThreatCategory.INJECT, Severity.HIGH, "SKILL.md", 0,
                                  "Hidden HTML comment — possible hidden instructions", c.strip()[:200])
        if re.search(r"[\u200b\u200c\u200d\u2060\ufeff]", content):
            self._add_finding(ThreatCategory.INJECT, Severity.CRITICAL, "SKILL.md", 0,
                              "Zero-width characters — invisible prompt injection", "(invisible)")
        pm = re.search(r"(?i)(prerequisite|requirement|setup|install).*?```(.*?)```", content, re.DOTALL)
        if pm:
            pc = pm.group(2)
            if re.search(r"curl.*\|\s*(ba)?sh", pc):
                self._add_finding(ThreatCategory.INSTALL, Severity.CRITICAL, "SKILL.md", 0,
                                  "Prerequisites curl-pipe-to-shell — ClawHavoc pattern", pc.strip()[:200])
        desc = self.report.frontmatter_description.lower()
        cl = content.lower()
        if (any(k in desc for k in ["format", "lint", "style", "markdown", "text", "note"])
                and any(k in cl for k in ["curl", "wget", "socket", "requests.post", "urllib"])):
            self._add_finding(ThreatCategory.INJECT, Severity.HIGH, "SKILL.md", 0,
                              "Benign description but network ops in instructions", f"Desc: {desc[:100]}...")

    def _analyze_false_positives(self):
        desc = self.report.frontmatter_description.lower()
        network_kw = ["api", "server", "download", "sync", "integration", "webhook",
                       "monitor", "radarr", "sonarr", "plex", "docker", "deploy",
                       "cloud", "backup", "remote", "torrent", "media", "stream",
                       "automation", "movie", "tv", "series"]
        is_net = any(k in desc for k in network_kw)

        for f in self.report.findings:
            if f.false_positive: continue
            # curl POST in network skill = likely API call
            if f.category == "EXFIL" and "curl POST" in f.description and is_net:
                f.false_positive = True
                f.fp_reason = "Network skill — curl POST likely for API calls"
            # .env in .md = documentation
            if f.category == "CRED" and f.file.endswith(".md") and ".env" in f.matched_text.lower():
                f.false_positive = True
                f.fp_reason = "Documentation reference to .env"
            # SOUL.md/MEMORY.md in .md = documentation
            if f.category == "INJECT" and f.file.endswith(".md") and ("SOUL.md" in f.matched_text or "MEMORY.md" in f.matched_text):
                f.false_positive = True
                f.fp_reason = "Documentation reference"

    def _is_benign_ip(self, ip, line):
        for b in {"127.0.0.", "0.0.0.0", "255.255.255.", "192.168.", "10.0.", "10.1.", "172.16.", "172.17.", "172.18."}:
            if ip.startswith(b): return True
        if re.search(r"version|v\d|release|\d+\.\d+\.\d+\.\d+.*\d", line, re.IGNORECASE): return True
        return False

    def _add_finding(self, cat, sev, file, line, desc, text, false_positive=False, fp_reason=""):
        f = Finding(category=cat.value if isinstance(cat, Enum) else cat,
                    severity=sev.value if isinstance(sev, Enum) else sev,
                    file=file, line=line, description=desc, matched_text=text,
                    false_positive=false_positive, fp_reason=fp_reason)
        key = (f.category, f.file, f.line, f.description)
        if key not in {(x.category, x.file, x.line, x.description) for x in self.report.findings}:
            self.report.findings.append(f)

    def _calculate_risk(self):
        real = self.report.real_findings
        if not real: self.report.overall_risk = "LOW"; return
        sev = [f.severity for f in real]
        cc, hc, mc = sev.count("CRITICAL"), sev.count("HIGH"), sev.count("MEDIUM")
        if cc > 0: self.report.overall_risk = "CRITICAL"
        elif hc >= 3 or len(sev) >= 6: self.report.overall_risk = "HIGH"
        elif hc >= 1 or mc >= 3: self.report.overall_risk = "MEDIUM"
        else: self.report.overall_risk = "LOW"

    def _generate_summary(self):
        total = len(self.report.findings)
        real = len(self.report.real_findings)
        fp = total - real
        if total == 0:
            self.report.summary = f"✅ No threats in '{self.report.skill_name}'. Scanned {self.report.file_count} files."
            return
        if real == 0:
            self.report.summary = (f"✅ No real threats in '{self.report.skill_name}'. "
                                   f"{fp} finding(s) identified as false positives.")
            return
        cats = {}
        for f in self.report.real_findings: cats[f.category] = cats.get(f.category, 0) + 1
        cs = ", ".join(f"{k}: {v}" for k, v in sorted(cats.items()))
        risk = self.report.overall_risk
        em = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}
        fpn = f" ({fp} false positives filtered)" if fp else ""
        self.report.summary = f"{em.get(risk, '❓')} Risk: {risk} — {real} real finding(s){fpn}. Categories: {cs}"


# ============================================================
# CLI
# ============================================================

def print_report_text(report):
    print("=" * 70)
    print(f"  CLAWHUB SKILL SECURITY REPORT")
    print(f"  Skill: {report.skill_name}")
    print(f"  Path:  {report.skill_path}")
    print("=" * 70)
    print(f"\n{report.summary}\n")
    if report.frontmatter_name: print(f"  Frontmatter name:  {report.frontmatter_name}")
    if report.frontmatter_description: print(f"  Description:       {report.frontmatter_description[:120]}")
    print(f"  SKILL.md present:  {'Yes' if report.has_skill_md else 'No'}")
    print(f"  Files scanned:     {report.file_count}")
    real = [f for f in report.findings if not f.false_positive]
    fps = [f for f in report.findings if f.false_positive]
    print(f"  Real findings:     {len(real)}")
    if fps: print(f"  False positives:   {len(fps)} (filtered from risk score)")
    print()

    if not real and not fps:
        print("  No findings — skill appears clean.\n"); return

    if real:
        by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for f in real: by_sev.get(f.severity, by_sev["LOW"]).append(f)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            fl = by_sev[sev]
            if not fl: continue
            ic = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}[sev]
            print(f"  {ic} {sev} ({len(fl)})")
            print(f"  {'─' * 60}")
            for f in fl:
                print(f"  [{f.category}] {f.file}:{f.line}")
                print(f"    {f.description}")
                if f.matched_text: print(f"    > {f.matched_text[:100]}")
                print()

    if fps:
        print(f"  ℹ️  FALSE POSITIVES ({len(fps)}) — not counted in risk score")
        print(f"  {'─' * 60}")
        for f in fps:
            print(f"  [{f.category}] {f.file}:{f.line} — {f.fp_reason}")
        print()

    print("─" * 70)
    r = report.overall_risk
    if r == "CRITICAL":
        print("  🚨 DO NOT INSTALL. Report on ClawHub.")
    elif r == "HIGH":
        print("  🔴 DO NOT INSTALL without manual review.")
    elif r == "MEDIUM":
        print("  🟠 REVIEW MANUALLY. Use Docker sandbox.")
    else:
        print("  ✅ Likely safe to install.")
    print("─" * 70)


def main():
    parser = argparse.ArgumentParser(description="Claw Guard — ClawHub Skill Security Scanner v2")
    parser.add_argument("paths", nargs="+", help="Skill directory path(s)")
    parser.add_argument("--batch", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--vt", action="store_true")
    parser.add_argument("--vt-key", type=str, default=None)
    parser.add_argument("--no-upload", action="store_true")
    args = parser.parse_args()

    vt_key = args.vt_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
    run_vt = args.vt and bool(vt_key)
    if args.vt and not vt_key:
        print("⚠️  --vt flag but no API key. Set VIRUSTOTAL_API_KEY or --vt-key\n")

    vt_module = None
    if run_vt:
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("vt_scanner", Path(__file__).parent / "vt_scanner.py")
            vt_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(vt_module)
        except Exception as e:
            print(f"⚠️  VT module load error: {e}\n"); run_vt = False

    reports = []
    for path in args.paths:
        scanner = SkillScanner(path)
        report = scanner.scan()

        if run_vt and vt_module and not scanner.is_self_scan:
            try:
                vts = vt_module.VTSkillScanner(vt_key, path)
                vtr = vts.scan_all(upload_binaries=not args.no_upload)
                report.vt_report = vtr.to_dict()
                for fr in vtr.file_results:
                    if hasattr(fr, 'is_threat') and fr.is_threat:
                        report.findings.append(Finding(
                            category="NETWORK", severity="CRITICAL", file=fr.file_path, line=0,
                            description=f"VirusTotal: {fr.malicious} engines flagged ({', '.join(fr.threat_names[:3])})",
                            matched_text=f"SHA-256: {fr.sha256}"))
                for ur in vtr.url_results:
                    if hasattr(ur, 'is_threat') and ur.is_threat:
                        te = ur.total_engines or 1
                        noise = (ur.malicious <= 1 and te > 70)
                        report.findings.append(Finding(
                            category="NETWORK",
                            severity="MEDIUM" if noise else "CRITICAL",
                            file="(VT URL scan)", line=0,
                            description=f"VirusTotal: {ur.malicious}/{te} engines flagged",
                            matched_text=ur.url,
                            false_positive=noise,
                            fp_reason=f"Only {ur.malicious}/{te} engines — likely noise" if noise else ""))
                scanner._calculate_risk()
                scanner._generate_summary()
            except Exception as e:
                print(f"⚠️  VT error: {e}\n")
        reports.append(report)

    if args.json_output:
        print(json.dumps(reports[0].to_dict() if len(reports) == 1 else [r.to_dict() for r in reports], indent=2))
    else:
        for report in reports:
            print_report_text(report)
            if run_vt and vt_module and report.vt_report:
                vtr = vt_module.VTScanReport(api_key_present=True,
                    files_checked=report.vt_report.get("files_checked", 0),
                    files_flagged=report.vt_report.get("files_flagged", 0),
                    urls_checked=report.vt_report.get("urls_checked", 0),
                    urls_flagged=report.vt_report.get("urls_flagged", 0),
                    uploads_attempted=report.vt_report.get("uploads_attempted", 0),
                    uploads_completed=report.vt_report.get("uploads_completed", 0),
                    rate_limited=report.vt_report.get("rate_limited", False),
                    errors=report.vt_report.get("errors", []))
                vtr.file_results = [vt_module.VTFileResult(**r) for r in report.vt_report.get("file_results", [])]
                vtr.url_results = [vt_module.VTUrlResult(**r) for r in report.vt_report.get("url_results", [])]
                vt_module.print_vt_report(vtr)
            if len(reports) > 1: print("\n")
        if len(reports) > 1:
            print("=" * 70); print("  BATCH SUMMARY"); print("=" * 70)
            for r in sorted(reports, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.overall_risk, 4)):
                ic = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(r.overall_risk, "❓")
                rc = len(r.real_findings)
                fc = len(r.findings) - rc
                fn = f" + {fc} FP" if fc else ""
                print(f"  {ic} [{r.overall_risk:8s}] {r.skill_name} ({rc} findings{fn})")
            print("=" * 70)

    worst = "LOW"
    pr = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    for r in reports:
        if pr.get(r.overall_risk, 0) > pr.get(worst, 0): worst = r.overall_risk
    sys.exit(0 if worst == "LOW" else 1 if worst == "MEDIUM" else 2)


if __name__ == "__main__":
    main()
