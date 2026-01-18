# Safer

## Overview
Safer is a command-line tool that scans archive files (ZIP, RAR, 7Z) with VirusTotal before extraction. It ensures potentially dangerous archives are identified and blocked before their contents can be accessed.

## Installation

### Prerequisites
- Python 3.6+
- VirusTotal API key (get from [virustotal.com](https://www.virustotal.com))
- 7-Zip installed for extraction

### Install 7-Zip
- **Windows**: Download from [7-zip.org](https://www.7-zip.org/)
- **Linux**: `sudo apt install p7zip-full` (Debian/Ubuntu) or `sudo yum install p7zip` (RHEL)
- **macOS**: `brew install p7zip`

## Quick Start

### Scan a single archive
```bash
python safer.py YOUR_API_KEY archive.zip
```

### Scan all archives in a folder
```bash
python safer.py YOUR_API_KEY ./Downloads
```

### Extract safe archives
```bash
python safer.py YOUR_API_KEY archive.zip --extract-to ./output
```

### Extract with full permissions
```bash
python safer.py YOUR_API_KEY archive.zip --extract-to ./output --unblock
```

### Extract all archives in a folder with full permissions
```bash
python safer.py YOUR_API_KEY ~/Downloads --extract-to ./output --unblock
```

## Features
- **Archive-only scanning**: Only processes ZIP, RAR, and 7Z files
- **Smart checking**: Calculates hash locally (safe for archives) and checks VirusTotal database first
- **Safe extraction**: Archives are only extracted if VirusTotal confirms they're clean
- **Permission control**: Option to set full permissions on extracted files
- **Bulk processing**: Scan individual files or entire folders
- **Extraction overwrite tracking**: Shows new vs updated files, **automatically overwrites** existing files

## Safety Design
- Local hash calculation is safe for archive files (no content execution)
- Mimics VirusTotal web interface behavior
- Blocks extraction if any threats are detected
- No force-extract option exists for maximum safety

## Command Line Options
- `api_key`: Your VirusTotal API key (required)
- `path`: Archive file or folder containing archives (required)
- `--extract-to DIRECTORY`: Extract safe archives to this directory (all files go directly here, no subfolders)
- `--unblock`: Set full permissions on extracted files (chmod ug+rwx on Linux, full control on Windows)

## Notes
- Large files may take time to upload and analyze
- Rate limits apply based on your VirusTotal account type
- Maximum file size: 650MB (VirusTotal limit)
