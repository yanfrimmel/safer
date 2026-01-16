# Safer

Command-line tool to scan files with VirusTotal API. Extracts archives only if safe.
I made this for my personal use for automating the processes of scanning downloaded archive files with VirusTotal and extracting.

## Quick Start

```bash
# Install dependencies
pip install requests

# Install 7-Zip (choose your OS)
# Windows: Download from 7-zip.org
# Ubuntu: sudo apt install p7zip-full
# macOS: brew install p7zip

# Get API key: https://virustotal.com/gui/join-us
```

## Usage

```bash
# Scan any file
python vt_scanner.py YOUR_API_KEY file.exe

# Scan archive (no extraction)
python vt_scanner.py YOUR_API_KEY archive.zip

# Extract only if safe
python vt_scanner.py YOUR_API_KEY archive.zip --extract-to ./output
```

## Safety Features

- **Always scans first** - File uploaded to VirusTotal before any processing
- **Blocks unsafe extraction** - If ANY threats detected, extraction is blocked
- **No force option** - Cannot bypass safety checks
- **Clear warnings** - Prominent alerts for dangerous files

## Examples

**Clean file:**
```
FILE IS CLEAN
Security Vendors Scanned: 62
Vendors Detected Threats: 0
```

**Dangerous file (extraction blocked):**
```
UNSAFE FILE DETECTED
Security Vendors Scanned: 65  
Vendors Detected Threats: 42

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! EXTRACTION BLOCKED!                              !
! This archive has 42 threat detection(s).         !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

## Arguments

- `api_key` - Your VirusTotal API key (required)
- `file` - File to scan (required)
- `--extract-to DIR` - Extract archive here if safe (optional)

## File Limits

- Max size: 650MB (VirusTotal limit)
- Supported archives: .zip, .7z, .rar
- Requires 7-Zip installed

## API Limits

- Free tier: 500 requests/day, 4/minute
- Wait 15 seconds between requests if limited
