#  SOCKET - Advanced Security Vulnerability Scanner v1.0

[![Java](https://img.shields.io/badge/Java-8%2B-blue.svg)](https://www.java.com/)
[![Security](https://img.shields.io/badge/Security-Testing-red.svg)](https://owasp.org/)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)]()

## Overview

SOCKET is a powerful, multi-threaded web application security scanner designed for penetration testing and vulnerability assessment. It automates the detection of common web vulnerabilities including SQL Injection, XSS, NoSQL Injection, XXE, SSTI, Path Traversal, and more.

## Disclaimer

**This tool is for educational and authorized testing purposes only!**
- Only use on systems you own or have explicit permission to test
- Unauthorized scanning may be illegal in your jurisdiction
- The author is not responsible for any misuse of this tool

## Features

| Category | Capabilities |
|----------|--------------|
| **SQL Injection** | Error-based, Boolean blind, Time-based, Union-based |
| **XSS** | Reflected, Stored, DOM-based, Template injection |
| **NoSQL Injection** | MongoDB operators, Authentication bypass |
| **File Inclusion** | LFI, RFI, Path Traversal |
| **Code Execution** | Command injection, SSTI, XXE |
| **WAF Detection** | Cloudflare, ModSecurity, AWS WAF, F5, Akamai, Imperva |
| **API Testing** | REST, JSON, XML endpoints |
| **Reporting** | HTML, JSON, XML reports with CVSS scoring |

## Installation

### Prerequisites
```bash
# Java 8 or higher
java -version

# For WebSocket testing (optional)
npm install ws
```
## Usage
```gitclone
git clone
cd SOCKET
```
***Basic Commands***
```basic
# Basic scan
java SOCKET -u https://example.com

# Scan with custom threads and depth
java SOCKET -u https://example.com -t 50 -d 5

# Scan with proxy
java SOCKET -u https://example.com --proxy 127.0.0.1:8080

# Scan with cookies (authenticated)
java SOCKET -u https://example.com --cookie "SESSION=abc123" --cookie "USER=admin"

# Scan with custom output
java SOCKET -u https://example.com -o report -f html

# Verbose mode
java SOCKET -u https://example.com -v
```
***Full Command Examples***
```full
# Comprehensive scan
java SOCKET -u https://testphp.vulnweb.com -t 30 -d 3 -m 500 -v -o vuln_report

# Authenticated scan
java SOCKET -u https://example.com --cookie "PHPSESSID=abc123" --cookie "security=low"

# Proxy scan (Burp Suite)
java SOCKET -u https://example.com --proxy 127.0.0.1:8080 -v

# JSON output
java SOCKET -u https://example.com -f json -o scan_result

# XML output
java SOCKET -u https://example.com -f xml -o scan_result
```
***Command Line Options***
```option
-u, --url <url>   Target URL  
-t, --threads <num>  Number of threads
-d, --depth <num>  Crawl depth
-m, --max-pages <num>  Miximum pages to scan
--proxy <host:port>   HTTP proxy
--cookie <cookie>  Add cookie (can be used multiple times)
-o, --output <file>  Output file name
-f, --format <format>  Output format (html json xml)
-v, --version  Enable verbose output
-h, --help  show help
```
***Console Output***
```show
====================================
        SOCKET - Version 3.0        
         Jailkrak - Bl4ckzus        
====================================

[+] Advanced Security Scanner Loaded
[+] SQLi | XSS | NoSQL | XXE | SSTI | Path Traversal
[+] Multi-threading | WAF Bypass | API Testing
[*] Target: https://testphp.vulnweb.com
[*] Threads: 30 | Max Pages: 500
[*] Starting scan...

[!] CRITICAL - SQL Injection found in https://testphp.vulnweb.com/artists.php?artist=1
    Evidence: SQL error: You have an error in your SQL syntax

[!] HIGH - XSS found in https://testphp.vulnweb.com/search.php?test=<script>alert(1)</script>
    Evidence: Payload reflected

[+] Scan completed in 45s
[+] Pages: 127 | Requests: 892
[+] Vulnerabilities: 8
```
## Testing Environments
***Safe testing***
```bash
# OWASP Vulnerable Web App (local)
http://localhost/dvwa/

# Google XSS Game
https://xss-game.appspot.com/

# Test PHP Vulnerable Web
http://testphp.vulnweb.com/

# WebGoat (local)
http://localhost:8080/WebGoat/
```
***Quick Reference Card***
```bash
# Quick commands
javac SOCKET.java                                    # Compile
java SOCKET -u https://target.com                    # Basic scan
java SOCKET -u https://target.com -t 50 -d 5 -v     # Advanced scan
java SOCKET -u https://target.com --proxy 127.0.0.1:8080  # With proxy
java SOCKET -u https://target.com -o report -f html # Save report
java SOCKET -h                                       # Help

# Examples with safe targets
java SOCKET -u http://testphp.vulnweb.com -v
java SOCKET -u https://xss-game.appspot.com/level1
```
***Contributing***

Fork the repository

Create feature branch

Commit changes

Push to branch

Open Pull Request

***License***

Educational Purpose Only - Use responsibly
