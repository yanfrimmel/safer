#!/usr/bin/env python3
"""
VirusTotal Archive Scanner - Scan archive files with optimal safety and efficiency
"""

import sys
import os
import argparse
import subprocess
import tempfile
import shutil
import requests
import time
import stat
import hashlib


class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "User-Agent": "VirusTotal-CLI/1.0"
        }
        self.large_file_threshold = 32 * 1024 * 1024  # 32MB

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of an archive file locally (SAFE for archives)"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None

    def scan_file(self, file_path):
        """Main method to scan an archive file - optimized like VirusTotal web interface"""
        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)

        print(f"File: {filename}")
        print(f"Size: {self._format_size(file_size)}")
        print("\n" + "="*60)

        # Step 1: Calculate hash locally (SAFE for archives)
        print("Calculating file hash (safe for archives)...")
        file_hash = self.calculate_file_hash(file_path)
        
        if not file_hash:
            print("Failed to calculate hash, uploading file directly...")
            return self._upload_and_scan(file_path, file_size)
        
        print(f"File SHA-256: {file_hash}")
        
        # Step 2: Check if file already exists in VirusTotal database
        print("Checking if file exists in VirusTotal database...")
        existing_analysis = self._get_existing_analysis(file_hash)
        
        if existing_analysis:
            print("✓ File found in database! Using existing analysis.")
            return file_hash, existing_analysis, True
        
        # Step 3: File doesn't exist, upload it
        print("File not found in database. Uploading for analysis...")
        return self._upload_and_scan(file_path, file_size, file_hash)

    def _upload_and_scan(self, file_path, file_size, known_hash=None):
        """Upload file and get analysis results"""
        filename = os.path.basename(file_path)

        print(f"Uploading: {filename}...")

        try:
            if file_size <= self.large_file_threshold:
                result = self._upload_small_file(file_path)
            else:
                result = self._upload_large_file(file_path, file_size)

            if not result:
                return None, None, False

            analysis_id, uploaded_hash, analysis_data = result
            
            # Use the hash we know or the one from upload
            final_hash = known_hash or uploaded_hash

            if analysis_data:
                # We got analysis data immediately
                return final_hash, analysis_data, False
            elif analysis_id:
                # Need to wait for analysis
                print("Waiting for new analysis...")
                analysis_data = self._get_analysis_results(analysis_id)
                return final_hash, analysis_data, False
            else:
                return None, None, False

        except Exception as e:
            print(f"Upload error: {e}")
            return None, None, False

    def _upload_small_file(self, file_path):
        """Upload files <= 32MB directly"""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=self.headers,
                    files=files,
                    timeout=30
                )

            return self._handle_upload_response(response)

        except Exception as e:
            print(f"Upload error: {e}")
            return None

    def _upload_large_file(self, file_path, file_size):
        """Upload files > 32MB using upload URL"""
        filename = os.path.basename(file_path)

        print(f"Large file detected ({self._format_size(
            file_size)}), getting upload URL...")

        try:
            response = requests.get(
                f"{self.base_url}/files/upload_url",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                upload_url = response.json()['data']
                print(f"Upload URL obtained")
            else:
                print(f"Failed to get upload URL: {response.status_code}")
                return None

        except Exception as e:
            print(f"Error getting upload URL: {e}")
            return None

        try:
            with open(file_path, 'rb') as f:
                files = {'file': (filename, f)}
                response = requests.post(
                    upload_url,
                    headers=self.headers,
                    files=files,
                    timeout=60
                )

            return self._handle_upload_response(response)

        except Exception as e:
            print(f"Upload error: {e}")
            return None

    def _handle_upload_response(self, response):
        """Handle upload response"""
        print(f"Response status: {response.status_code}")

        if response.status_code == 200:
            try:
                data = response.json()

                analysis_id = None
                if 'data' in data and 'id' in data['data']:
                    analysis_id = data['data']['id']

                file_hash = self._extract_hash_from_response(data)

                # Check for immediate results
                analysis_data = None
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']

                    if 'results' in attributes or 'last_analysis_results' in attributes:
                        print("✓ File uploaded with immediate analysis results")
                        
                        analysis_data = {
                            'data': {
                                'id': analysis_id or 'immediate',
                                'attributes': {
                                    'status': 'completed',
                                    'stats': attributes.get('last_analysis_stats', {}),
                                    'results': attributes.get('last_analysis_results', attributes.get('results', {}))
                                }
                            }
                        }

                        if not analysis_data['data']['attributes']['stats'] and analysis_data['data']['attributes']['results']:
                            results = analysis_data['data']['attributes']['results']
                            analysis_data['data']['attributes']['stats'] = self._calculate_stats_from_results(
                                results)

                if analysis_data:
                    return analysis_id, file_hash, analysis_data
                else:
                    print(f"Upload successful. Analysis ID: {analysis_id}")
                    if file_hash:
                        print(f"File SHA-256 (from VirusTotal): {file_hash}")
                    return analysis_id, file_hash, None

            except Exception as e:
                print(f"Error parsing upload response: {e}")
                return None

        elif response.status_code == 409:
            print("File already exists in VirusTotal database")
            return None

        else:
            print(f"Upload failed: {response.status_code}")
            if response.status_code == 401:
                print("Error: Invalid API key")
            elif response.status_code == 429:
                print("Error: API rate limit exceeded")
            elif response.status_code == 403:
                print("Error: Forbidden - check API permissions")
            else:
                error_text = response.text[:500] if response.text else "No error details"
                print(f"Error: {error_text}")
            return None

    def _extract_hash_from_response(self, data):
        """Extract file hash from successful response data"""
        locations = [
            ['data', 'attributes', 'sha256'],
            ['data', 'attributes', 'file_info', 'sha256'],
            ['meta', 'file_info', 'sha256'],
            ['data', 'sha256'],
        ]

        for location in locations:
            try:
                current = data
                for key in location:
                    current = current[key]
                if current and isinstance(current, str) and len(current) == 64:
                    return current
            except:
                continue

        return None

    def _get_existing_analysis(self, file_hash):
        """Get existing analysis for a file hash"""
        try:
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']

                    if 'last_analysis_results' in attributes or 'results' in attributes:
                        analysis_data = {
                            'data': {
                                'id': data['data']['id'],
                                'attributes': {
                                    'status': 'completed',
                                    'stats': attributes.get('last_analysis_stats', {}),
                                    'results': attributes.get('last_analysis_results', {}),
                                    'last_analysis_date': attributes.get('last_analysis_date'),
                                    'last_modification_date': attributes.get('last_modification_date'),
                                    'first_submission_date': attributes.get('first_submission_date'),
                                    'last_submission_date': attributes.get('last_submission_date')
                                }
                            }
                        }

                        if not analysis_data['data']['attributes']['stats'] and analysis_data['data']['attributes']['results']:
                            results = analysis_data['data']['attributes']['results']
                            stats = self._calculate_stats_from_results(results)
                            analysis_data['data']['attributes']['stats'] = stats

                        return analysis_data
                    
            return None

        except Exception as e:
            print(f"Error checking existing analysis: {e}")
            return None

    def _calculate_stats_from_results(self, results):
        """Calculate stats from analysis results"""
        stats = {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0
        }

        for result in results.values():
            category = result.get('category')
            if category == 'malicious':
                stats['malicious'] += 1
            elif category == 'suspicious':
                stats['suspicious'] += 1
            elif category == 'harmless':
                stats['harmless'] += 1
            else:
                stats['undetected'] += 1

        return stats

    def _get_analysis_results(self, analysis_id):
        """Get analysis results for an analysis ID"""
        print(f"Getting analysis results for ID: {analysis_id}")

        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                response = requests.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and 'attributes' in data['data']:
                        status = data['data']['attributes']['status']

                        if status == 'completed':
                            print(f"Analysis completed")
                            return data
                        elif attempt == 0:
                            print(
                                f"Status: {status} (checking every 10 seconds)")
                        elif (attempt + 1) % 3 == 0:
                            print(f"Still analyzing... ({
                                  attempt + 1}/30 attempts)")
                    else:
                        print(f"Unexpected analysis response format")
                else:
                    print(f"Analysis check failed: {response.status_code}")

                time.sleep(10)

            except requests.exceptions.ConnectionError:
                print("Connection error, retrying...")
                time.sleep(10)
            except Exception as e:
                print(f"Error checking status: {e}")
                time.sleep(10)

        print("Timeout: Analysis took too long")
        return None

    def display_results(self, analysis_data, file_hash=None):
        """Display scan results including last analysis date"""
        if not analysis_data:
            print("No analysis data available")
            return 0

        try:
            if 'data' in analysis_data and 'attributes' in analysis_data['data']:
                attributes = analysis_data['data']['attributes']

                results = attributes.get('results', {})
                if not results:
                    results = attributes.get('last_analysis_results', {})

                stats = attributes.get('stats', {})
                if not stats:
                    stats = attributes.get('last_analysis_stats', {})
                if not stats and results:
                    stats = self._calculate_stats_from_results(results)

                last_analysis_date = "Not available"
                date_fields = ['last_analysis_date', 'last_modification_date',
                               'first_submission_date', 'last_submission_date']

                for field in date_fields:
                    if field in attributes:
                        timestamp = attributes[field]
                        if timestamp:
                            try:
                                import datetime
                                last_analysis_date = datetime.datetime.fromtimestamp(
                                    int(timestamp)
                                ).strftime('%Y-%m-%d %H:%M:%S Local time')
                                break
                            except:
                                last_analysis_date = str(timestamp)
                                break

                if not results:
                    print("No analysis results found")
                    return 0

                total_vendors = len(results)
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_detections = malicious + suspicious

                print("\n" + "="*60)
                print("VIRUSTOTAL SCAN RESULTS")
                print("="*60)

                if file_hash:
                    print(f"File SHA-256: {file_hash}")
                    print("-" * 60)

                print(f"Security Vendors Scanned: {total_vendors}")
                print(f"Vendors Detected Threats: {total_detections}")
                print(f"Last Analysis Date: {last_analysis_date}")
                print("-" * 60)

                if total_detections > 0:
                    print("UNSAFE FILE DETECTED")
                    print(f"  Malicious detections: {malicious}")
                    print(f"  Suspicious detections: {suspicious}")
                    print(f"  Harmless: {stats.get('harmless', 0)}")
                    print(f"  Undetected: {stats.get('undetected', 0)}")

                    print("\nDETECTION DETAILS:")
                    detection_count = 0
                    for vendor, result in results.items():
                        if result.get('category') in ['malicious', 'suspicious']:
                            result_text = result.get(
                                'result', 'Unknown threat')
                            method = result.get('method', '')
                            if method:
                                print(f"  {vendor}: {result_text} ({method})")
                            else:
                                print(f"  {vendor}: {result_text}")
                            detection_count += 1
                            if detection_count >= 5:
                                if total_detections > 5:
                                    print(f"  ... and {
                                          total_detections - 5} more detections")
                                break
                else:
                    print("FILE IS CLEAN")
                    print(f"  Harmless: {stats.get('harmless', 0)}")
                    print(f"  Undetected: {stats.get('undetected', 0)}")

                print("="*60)

                return total_detections
            else:
                print("Invalid analysis data structure")
                return 0

        except Exception as e:
            print(f"Error displaying results: {e}")
            return 0

    def _format_size(self, size_bytes):
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"


def format_bytes(size_bytes):
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def check_7z_installed():
    """Check if 7z is available on the system"""
    try:
        subprocess.run(['7z', '--help'],
                       capture_output=True,
                       check=False,
                       timeout=2)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def extract_archive(archive_path, extract_dir=None):
    """Extract archive using 7z command-line tool"""
    if not check_7z_installed():
        print("Error: 7z is not installed or not in PATH")
        print("Please install 7-Zip:")
        print("  Windows: https://www.7-zip.org/")
        print("  Linux: sudo apt install p7zip-full (Debian/Ubuntu)")
        print("         sudo yum install p7zip (RHEL/CentOS)")
        print("  macOS: brew install p7zip")
        return None

    archive_ext = os.path.splitext(archive_path)[1].lower()
    supported_extensions = ['.zip', '.7z', '.rar']

    if archive_ext not in supported_extensions:
        print(f"Unsupported archive format: {archive_ext}")
        print(f"Supported formats: {', '.join(supported_extensions)}")
        return None

    if extract_dir is None:
        extract_dir = tempfile.mkdtemp(prefix="vt_extract_")
        is_temp = True
    else:
        os.makedirs(extract_dir, exist_ok=True)
        is_temp = False

    print(f"\nExtracting {archive_ext.upper()} archive...")
    print(f"Destination: {extract_dir}")

    try:
        result = subprocess.run(
            ['7z', 'x', archive_path, f'-o{extract_dir}', '-y'],
            capture_output=True,
            text=True,
            check=False,
            timeout=60
        )

        if result.returncode == 0:
            extracted_files = []
            total_size = 0

            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    extracted_files.append(file_path)
                    total_size += file_size

            if extracted_files:
                print(f"Extraction successful")
                print(f"Extracted {len(extracted_files)} file(s), total: {
                      format_bytes(total_size)}")

                print("\nExtracted files (first 10):")
                for i, file_path in enumerate(extracted_files[:10]):
                    rel_path = os.path.relpath(file_path, extract_dir)
                    size = os.path.getsize(file_path)
                    print(f"  {i+1:2d}. {rel_path} ({format_bytes(size)})")

                if len(extracted_files) > 10:
                    print(f"  ... and {len(extracted_files) - 10} more files")

                return extract_dir
            else:
                print("No files found after extraction")
                if is_temp:
                    try:
                        shutil.rmtree(extract_dir)
                    except:
                        pass
                return None
        else:
            print(f"Extraction failed with code: {result.returncode}")
            if result.stderr:
                error_lines = result.stderr.strip().split('\n')
                if error_lines:
                    print(f"Error: {error_lines[-1][:100]}")
            return None

    except subprocess.TimeoutExpired:
        print("Extraction timeout (60 seconds)")
        return None
    except Exception as e:
        print(f"Extraction error: {e}")
        return None


def unblock_files_and_dirs(path):
    """
    Set full permissions on files and directories.
    Linux: chmod ug+rwx (user and group read/write/execute)
    Windows: icacls (grant full control)
    """
    print(f"Setting permissions on: {path}")
    
    if not os.path.exists(path):
        print(f"Warning: Path does not exist: {path}")
        return False
    
    try:
        if sys.platform.startswith('win'):
            # Windows: Grant full control to current user
            username = os.getlogin()
            
            # Use icacls command
            cmd = f'icacls "{path}" /grant "{username}:(OI)(CI)F" /T /Q'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"Windows permissions set for user '{username}'")
                return True
            else:
                print(f"Windows permission setting failed: {result.stderr}")
                
                # Fallback: Try basic Python method
                try:
                    # Make writable using Python
                    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                    
                    # If it's a directory, apply recursively
                    if os.path.isdir(path):
                        for root, dirs, files in os.walk(path):
                            for dir_name in dirs:
                                dir_path = os.path.join(root, dir_name)
                                os.chmod(dir_path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                            for file_name in files:
                                file_path = os.path.join(root, file_name)
                                os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                    
                    print("Fallback permissions set (basic Python method)")
                    return True
                    
                except Exception as e:
                    print(f"Fallback permission setting failed: {e}")
                    return False
                    
        else:
            # Linux/macOS: Use chmod
            # First set permissions on the item itself
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |  # User: rwx
                             stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP)  # Group: rwx
            
            # If it's a directory, apply recursively
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        os.chmod(dir_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                                         stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP)
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        # For files, keep execute bit only if it was already executable
                        current_mode = os.stat(file_path).st_mode
                        new_mode = (stat.S_IRUSR | stat.S_IWUSR |  # User: rw
                                    stat.S_IRGRP | stat.S_IWGRP)   # Group: rw
                        
                        # Preserve execute bits if they exist
                        if current_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                            new_mode |= (stat.S_IXUSR | stat.S_IXGRP)
                        
                        os.chmod(file_path, new_mode)
            
            print("Linux/macOS permissions set: chmod ug+rwx (recursive)")
            return True
            
    except Exception as e:
        print(f"Error setting permissions: {e}")
        return False


def get_files_from_path(input_path):
    """
    Get list of files from a path (file or directory)
    Only returns archive files (ZIP, RAR, 7Z)
    """
    file_paths = []
    
    if os.path.isfile(input_path):
        # Check if it's an archive
        file_ext = os.path.splitext(input_path)[1].lower()
        if file_ext in ['.zip', '.7z', '.rar']:
            file_paths.append(input_path)
        else:
            print(f"Error: '{input_path}' is not a supported archive file!")
            print("This tool only scans archive files (ZIP, 7Z, RAR)")
            return []
    elif os.path.isdir(input_path):
        # Directory - get all archive files
        for root, dirs, files in os.walk(input_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1].lower()
                
                if file_ext in ['.zip', '.7z', '.rar']:
                    # Skip files larger than VirusTotal limit
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size <= 650 * 1024 * 1024:  # 650MB limit
                            file_paths.append(file_path)
                        else:
                            print(f"Skipping large file: {file} ({format_bytes(file_size)})")
                    except:
                        continue
    else:
        print(f"Error: Path '{input_path}' does not exist")
        return []
    
    return file_paths


def confirm_action(prompt):
    """Ask for user confirmation"""
    while True:
        response = input(f"{prompt} (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            return True
        if response in ['n', 'no', '']:
            return False
        print("Please enter 'y' for yes or 'n' for no")


def print_warning_box(message):
    """Print a warning in a box"""
    lines = message.split('\n')
    max_len = max(len(line) for line in lines)
    border = "!" * (max_len + 4)

    print(f"\n{border}")
    for line in lines:
        print(f"! {line.ljust(max_len)} !")
    print(f"{border}\n")


def main():
    parser = argparse.ArgumentParser(
        description='VirusTotal Archive Scanner - Scan archive files with optimal safety and efficiency',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ARCHIVE SCANNER:
• Only processes ZIP, RAR, and 7Z files
• Calculates hash locally (SAFE for archives)
• Only uploads files that don't exist in VirusTotal
• Extracts archives only if they are safe

Safety Design:
• Local hash calculation is SAFE for archive files
• Mimics VirusTotal web interface behavior
• Maximum efficiency - avoids unnecessary uploads

Examples:
  %(prog)s YOUR_API_KEY archive.zip
  %(prog)s YOUR_API_KEY ./archives_folder --extract-to ./output
  %(prog)s YOUR_API_KEY archive.rar --extract-to ./output --unblock
        """
    )

    parser.add_argument('api_key', help='VirusTotal API key')
    parser.add_argument('path', help='Archive file or folder containing archives to scan')
    parser.add_argument('--extract-to', metavar='DIRECTORY',
                        help='Extract ALL archives to this directory (only if safe). Files extracted directly to this directory, no subfolders.')
    parser.add_argument('--unblock', action='store_true',
                        help='Set full permissions on extracted files (chmod ug+rwx on Linux, full control on Windows)')

    args = parser.parse_args()

    # Check if path exists
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' not found!")
        sys.exit(1)

    # Initialize scanner
    scanner = VirusTotalScanner(args.api_key)

    # Get all archive files from the path
    print(f"Source: {args.path}")
    if os.path.isdir(args.path):
        print(f"Type: Directory (scanning for archives only)")
    else:
        file_ext = os.path.splitext(args.path)[1].lower()
        print(f"Type: {file_ext.upper()} Archive")
    
    if args.extract_to:
        print(f"Extract to: {args.extract_to} (all archives extracted directly here)")
    if args.unblock:
        print(f"Permission setting: Enabled")
    
    print("\n" + "="*60)
    
    # Get list of archive files to scan
    file_paths = get_files_from_path(args.path)
    
    if not file_paths:
        print("No archive files found to scan")
        sys.exit(1)
    
    print(f"Found {len(file_paths)} archive file(s) to scan")
    
    # Statistics
    total_files = len(file_paths)
    safe_files = 0
    unsafe_files = 0
    failed_files = 0
    extracted_archives = 0
    
    # Create main extraction directory if specified
    main_extract_dir = args.extract_to
    if main_extract_dir:
        os.makedirs(main_extract_dir, exist_ok=True)
        print(f"\nAll safe archives will be extracted directly to: {main_extract_dir}")
        print("(No subfolders will be created for individual archives)")
    
    # Scan each file
    for i, file_path in enumerate(file_paths, 1):
        print(f"\n{'='*60}")
        print(f"SCANNING ARCHIVE {i}/{total_files}")
        print(f"{'='*60}")
        
        file_name = os.path.basename(file_path)
        
        # Check file size (VirusTotal has limits)
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 650 * 1024 * 1024:
                print(f"Skipping: {file_name} (too large: {format_bytes(file_size)})")
                failed_files += 1
                continue
        except:
            print(f"Skipping: {file_name} (cannot access)")
            failed_files += 1
            continue
        
        # Scan the file - uses optimal web interface approach
        file_hash, analysis_data, is_existing = scanner.scan_file(file_path)

        if not analysis_data:
            print(f"Failed to get analysis for: {file_name}")
            failed_files += 1
            continue

        # Display results
        total_detections = scanner.display_results(analysis_data, file_hash)
        
        # Check if we should extract
        should_extract = main_extract_dir is not None
        
        if should_extract:
            print(f"\n{'='*60}")
            print(f"ARCHIVE PROCESSING: {file_name}")
            print(f"{'='*60}")
            
            if total_detections > 0:
                # UNSAFE - BLOCK EXTRACTION
                print_warning_box(f"""
EXTRACTION BLOCKED!
This archive has {total_detections} threat detection(s).

File: {file_name}
SHA-256: {file_hash}

SAFETY ACTION:
• Archive will NOT be extracted
• Handle with extreme caution
                """)
                unsafe_files += 1
                
            else:
                # SAFE - Extract
                print(f"Archive is clean - Safe to extract")
                print(f"File SHA-256: {file_hash}")
                
                # Extract directly to the main directory (no subfolder)
                print(f"Extracting directly to: {main_extract_dir}")
                
                extract_dir = extract_archive(file_path, main_extract_dir)
                if extract_dir:
                    print(f"Archive successfully extracted to main directory")
                    extracted_archives += 1
                    safe_files += 1
                    
                    # Apply permission unblocking if requested
                    if args.unblock:
                        print(f"\nSetting permissions on extracted files...")
                        success = unblock_files_and_dirs(main_extract_dir)
                        if success:
                            print(f"Permissions successfully set on {main_extract_dir}")
                        else:
                            print(f"Warning: Could not set all permissions")
                else:
                    print(f"Extraction failed")
                    failed_files += 1
                    
        else:
            # Archive scan without extraction request
            if total_detections > 0:
                print_warning_box(f"""
WARNING: UNSAFE ARCHIVE DETECTED
File: {file_name}
Detections: {total_detections}
SHA-256: {file_hash}

Recommendation: Delete this file immediately.
                """)
                unsafe_files += 1
            else:
                print(f"\nArchive is clean: {file_name}")
                safe_files += 1
        
        # Small delay between files to avoid rate limiting
        if i < total_files:
            print(f"\n{'='*60}")
            print("Waiting 2 seconds before next file...")
            print(f"{'='*60}")
            time.sleep(2)
    
    # Print summary
    print(f"\n{'='*60}")
    print("SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"Total archives scanned: {total_files}")
    print(f"  Safe archives: {safe_files}")
    print(f"  Unsafe archives: {unsafe_files}")
    print(f"  Failed archives: {failed_files}")
    
    if main_extract_dir:
        print(f"Archives extracted: {extracted_archives}")
        print(f"All safe archives extracted directly to: {main_extract_dir}")
    
    if unsafe_files > 0:
        print(f"\nWARNING: {unsafe_files} unsafe archive(s) detected!")
        print("Recommendation: Delete or quarantine unsafe archives.")
    
    if main_extract_dir:
        print(f"\nExtracted files location: {main_extract_dir}")
        print("Note: All archives were extracted directly to this directory")
        print("      No subfolders were created for individual archives")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
