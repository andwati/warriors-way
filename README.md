# warriors way - CybersecurityLearning Checklist

## Web Application Security

### Core Web Security Concepts

- [ ] HTTP/HTTPS, status codes, methods
- [ ] Cookies, sessions, and token-based auth
- [ ] Same-Origin Policy (SOP)
- [ ] Cross-Origin Resource Sharing (CORS)
- [ ] Content Security Policy (CSP)
- [ ] Secure HTTP headers (HSTS, X-Frame-Options, etc.)

### OWASP Top 10 (2021)

- [ ] A01: Broken Access Control
- [ ] A02: Cryptographic Failures
- [ ] A03: Injection (SQLi, NoSQLi, etc.)
- [ ] A04: Insecure Design
- [ ] A05: Security Misconfiguration
- [ ] A06: Vulnerable and Outdated Components
- [ ] A07: Identification and Authentication Failures
- [ ] A08: Software and Data Integrity Failures
- [ ] A09: Security Logging and Monitoring Failures
- [ ] A10: Server-Side Request Forgery (SSRF)

### Common Vulnerabilities & Attacks

- [ ] Cross-Site Scripting (XSS) - Reflected, Stored, DOM
- [ ] Cross-Site Request Forgery (CSRF)
- [ ] Insecure Direct Object References (IDOR)
- [ ] File upload vulnerabilities
- [ ] Path traversal attacks
- [ ] Local/Remote File Inclusion (LFI/RFI)
- [ ] Clickjacking
- [ ] Broken authentication (session hijacking, fixation)
- [ ] Business logic vulnerabilities
- [ ] Race conditions

### Web Security Practices

- [ ] Input validation and sanitization
- [ ] Output encoding
- [ ] Rate limiting and throttling
- [ ] Secure password storage (bcrypt, Argon2, etc.)
- [ ] Session management best practices
- [ ] Secrets management (Vault, AWS Secrets Manager)
- [ ] Dependency vulnerability scanning (Snyk, OWASP Dependency-Check)

## Penetration Testing

### Core Concepts

- [ ] Penetration testing methodology (recon, exploit, post-exploit)
- [ ] Vulnerability scanning vs. pentesting
- [ ] Threat modeling and attack surface analysis

### Reconnaissance

- [ ] OSINT (Shodan, Google Dorks, Recon-ng)
- [ ] DNS enumeration, subdomain discovery
- [ ] WHOIS lookups, IP range scans
- [ ] Web crawling and scraping

### Exploitation

- [ ] Exploiting common web vulns (XSS, SQLi, CSRF, etc.)
- [ ] Exploiting APIs and mobile apps
- [ ] Exploiting misconfigured cloud services
- [ ] SSRF, XXE, deserialization attacks
- [ ] Command injection, RCE

### Post-Exploitation

- [ ] Privilege escalation
- [ ] Session/token theft
- [ ] Credential reuse
- [ ] Data exfiltration techniques
- [ ] Persistence techniques

### Pentesting Tools

- [ ] Burp Suite
- [ ] OWASP ZAP
- [ ] Nikto
- [ ] Nmap
- [ ] Metasploit
- [ ] sqlmap
- [ ] ffuf / dirb / gobuster
- [ ] wfuzz
- [ ] JWT toolkits (jwt.io, jwt_tool)

## General Cybersecurity Topics

### Cryptography

- [ ] Symmetric vs. asymmetric encryption
- [ ] Hashing (MD5, SHA, bcrypt, Argon2)
- [ ] TLS/SSL and HTTPS
- [ ] Certificate pinning
- [ ] Key exchange protocols (Diffie-Hellman, RSA)
- [ ] Common cryptographic attacks (padding oracle, timing attacks)

### Secure Software Development

- [ ] Secure SDLC (Software Development Lifecycle)
- [ ] Threat modeling (STRIDE, DREAD)
- [ ] Static and dynamic analysis (SAST/DAST)
- [ ] Code reviews with security focus
- [ ] Secure CI/CD pipelines

### Network Security

- [ ] TCP/IP, ports, protocols
- [ ] Firewall basics and configuration
- [ ] VPNs and tunneling
- [ ] Packet sniffing and spoofing
- [ ] IDS/IPS systems
- [ ] DNS poisoning, ARP spoofing

### Cloud Security

- [ ] Shared responsibility model
- [ ] IAM policies and roles
- [ ] S3 bucket security
- [ ] Cloud pentesting tools (ScoutSuite, Prowler)
- [ ] Azure/GCP/AWS specific misconfigurations

### Endpoint & System Security

- [ ] Linux hardening (AppArmor, SELinux)
- [ ] Windows internals and defenses
- [ ] Malware analysis basics
- [ ] Forensics fundamentals
- [ ] Logging and monitoring best practices

## Optional Advanced Topics

### Red Teaming / Adversary Simulation

- [ ] C2 frameworks (Covenant, Cobalt Strike)
- [ ] Lateral movement techniques
- [ ] Social engineering tactics
- [ ] Custom payload development

### Blue Teaming / Defense

- [ ] SIEM (Splunk, ELK)
- [ ] EDR/XDR tools
- [ ] Log correlation and threat detection
- [ ] MITRE ATT&CK framework
- [ ] Incident response planning and execution

### Certifications to Explore

- [ ] CompTIA Security+
- [ ] Offensive Security Certified Professional (OSCP)
- [ ] Certified Ethical Hacker (CEH)
- [ ] GIAC Web Application Penetration Tester (GWAPT)
- [ ] eLearnSecurity eWPT

## Advanced Cybersecurity Topics (Additions)

### Red Teaming / Offensive Security

- [ ] Advanced payload obfuscation techniques
- [ ] Phishing campaign simulation
- [ ] C2 frameworks (Cobalt Strike, Sliver, Mythic)
- [ ] Initial access techniques (maldocs, DLL sideloading)
- [ ] Lateral movement (WMI, PsExec, pass-the-hash)
- [ ] Kerberoasting & AS-REP Roasting
- [ ] Windows Active Directory exploitation
- [ ] Bypassing EDR and antivirus
- [ ] Post-exploitation persistence methods
- [ ] Tunneling and pivoting

### Blue Teaming / Defensive Security

- [ ] Log aggregation and correlation (SIEM tools)
- [ ] Threat hunting strategies
- [ ] Creating detection rules (Sigma, YARA)
- [ ] Memory analysis (Volatility, Rekall)
- [ ] File integrity monitoring
- [ ] DNS sinkholing
- [ ] Incident response tabletop exercises
- [ ] MITRE ATT&CK navigator mapping
- [ ] Threat intelligence sources & feeds
- [ ] Security operations center (SOC) workflows

### Secure DevOps / DevSecOps

- [ ] Infrastructure as Code (IaC) security
- [ ] Secrets scanning in code (Gitleaks, TruffleHog)
- [ ] Container hardening (Docker, Kubernetes)
- [ ] SBOMs and software supply chain security
- [ ] Runtime security for containers (Falco, AppArmor)
- [ ] Policy as Code (OPA, Kyverno)
- [ ] CI/CD pipeline threat modeling
- [ ] Static analysis in pipelines
- [ ] Pre-commit security hooks
- [ ] Canary deployments and rollback strategies

### Cloud Security (Advanced)

- [ ] Cloud identity privilege escalation paths
- [ ] IAM misconfiguration exploitation
- [ ] CSPM tools (CloudSploit, Prowler, ScoutSuite)
- [ ] Cloud key leakage and token abuse
- [ ] Cloud logging and auditing (CloudTrail, Azure Monitor)
- [ ] Serverless security (Lambda, Azure Functions)
- [ ] Cloud infrastructure drift detection
- [ ] Multi-cloud security posture management
- [ ] KMS and key lifecycle policies
- [ ] Resource-based vs. identity-based policies

### Advanced Tooling & Techniques

- [ ] Malware sandboxing and dynamic analysis
- [ ] Reverse engineering binaries
- [ ] Firmware and hardware exploitation basics
- [ ] Network protocol fuzzing
- [ ] Developing custom Metasploit modules
- [ ] Memory corruption vulnerabilities (BOF, Use-After-Free)
- [ ] Symbolic execution and static binary analysis
- [ ] Exploit mitigation bypass techniques (DEP, ASLR)
- [ ] Kernel-level debugging
- [ ] Threat emulation with Atomic Red Team

## Additional Learning & Certifications

- [ ] MITRE ATT&CK and D3FEND frameworks
- [ ] Cyber Kill Chain model
- [ ] Threat modeling frameworks (PASTA, LINDDUN)
- [ ] Cybersecurity risk assessment (ISO/IEC 27005)
- [ ] OSCE / OSWE (Offensive Security certs)
- [ ] GIAC GCPN / GCLD / GNFA / GCIA
- [ ] Red vs. Blue team simulated environments (RangeForce, Cyber Ranges)
- [ ] Building home lab for practice (Proxmox/VMware, AD labs)
