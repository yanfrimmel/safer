#!/usr/bin/env python3
"""
VirusTotal File Scanner - Smart scanning that avoids unnecessary uploads
"""

import sys
import os
import argparse
import subprocess
import tempfile
import shutil
import requests
import time
import hashlib


class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "User-Agent": "VirusTotal-CLI/1.0"
        }
        self.large_file_threshold = 32 * 1024 * 1024  # 32MB

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file locally"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_file(self, file_path):
        """Main method to scan a file - tries to avoid re-uploading"""
        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)

        print(f"File: {filename}")
        print(f"Size: {self._format_size(file_size)}")

        # Calculate hash locally first
        print("Calculating file hash...")
        file_hash = self.calculate_file_hash(file_path)
        print(f"File SHA-256: {file_hash}")

        print("\n" + "="*60)

        # Step 1: First check if file already exists in VirusTotal
        print("Checking if file exists in VirusTotal database...")
        existing_analysis = self._get_existing_analysis(file_hash)

        if existing_analysis:
            print("File found in database! Using existing analysis.")
            return file_hash, existing_analysis, True

        # Step 2: File doesn't exist, upload it
        print("File not found in database. Uploading for analysis...")
        result = self._upload_file(file_path, file_size)

        if not result:
            return None, None, False

        analysis_id, uploaded_hash, analysis_data = result

        if analysis_data:
            # We got analysis data immediately
            return uploaded_hash or file_hash, analysis_data, False
        elif analysis_id:
            # Need to wait for analysis
            print("Waiting for new analysis...")
            analysis_data = self._get_analysis_results(analysis_id)
            return uploaded_hash or file_hash, analysis_data, False
        else:
            return None, None, False

    def _get_existing_analysis(self, file_hash):
        """Get existing analysis for a file hash"""
        try:
            print(f"Fetching analysis for hash: {file_hash}")
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                # Extract analysis from file info
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']

                    # Check if we have analysis results
                    if 'last_analysis_results' in attributes or 'results' in attributes:
                        print("Found existing analysis in database")

                        # IMPORTANT: We need to restructure the data to match what display_results expects
                        # VirusTotal file info response has different structure than analysis response
                        analysis_data = {
                            'data': {
                                'id': data['data']['id'],
                                'attributes': {
                                    'status': 'completed',
                                    'stats': attributes.get('last_analysis_stats', {}),
                                    'results': attributes.get('last_analysis_results', {}),
                                    # Also include date fields for display
                                    'last_analysis_date': attributes.get('last_analysis_date'),
                                    'last_modification_date': attributes.get('last_modification_date'),
                                    'first_submission_date': attributes.get('first_submission_date'),
                                    'last_submission_date': attributes.get('last_submission_date')
                                }
                            }
                        }

                        # If we have results but no stats, calculate stats
                        if not analysis_data['data']['attributes']['stats'] and analysis_data['data']['attributes']['results']:
                            results = analysis_data['data']['attributes']['results']
                            stats = self._calculate_stats_from_results(results)
                            analysis_data['data']['attributes']['stats'] = stats

                        return analysis_data
                    else:
                        print("File exists but no analysis results available")
                        return None
                else:
                    print("Unexpected response format")
                    return None
            elif response.status_code == 404:
                print("File not found in VirusTotal database")
                return None
            else:
                print(f"Failed to get file info: {response.status_code}")
                return None

        except Exception as e:
            print(f"Error getting existing analysis: {e}")
            return None

    def _upload_file(self, file_path, file_size):
        """Upload file to VirusTotal and return (analysis_id, file_hash, analysis_data)"""
        filename = os.path.basename(file_path)

        print(f"Uploading: {filename}...")

        try:
            if file_size <= self.large_file_threshold:
                return self._upload_small_file(file_path)
            else:
                return self._upload_large_file(file_path, file_size)

        except Exception as e:
            print(f"Upload error: {e}")
            return None

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

        # Step 1: Get upload URL for large file
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

        # Step 2: Upload file to the special URL
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
        """Handle upload response - extract analysis ID, hash, and check for immediate analysis"""
        print(f"Response status: {response.status_code}")

        if response.status_code == 200:
            try:
                data = response.json()

                # Extract analysis ID
                analysis_id = None
                if 'data' in data and 'id' in data['data']:
                    analysis_id = data['data']['id']

                # Extract file hash
                file_hash = self._extract_hash_from_response(data)

                # Check if we have immediate analysis results
                analysis_data = None
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']

                    # Check for analysis results
                    if 'results' in attributes or 'last_analysis_results' in attributes:
                        print("File uploaded and analysis available immediately")

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

                        # Calculate stats if needed
                        if not analysis_data['data']['attributes']['stats'] and analysis_data['data']['attributes']['results']:
                            results = analysis_data['data']['attributes']['results']
                            analysis_data['data']['attributes']['stats'] = self._calculate_stats_from_results(
                                results)

                if analysis_data:
                    return analysis_id, file_hash, analysis_data
                else:
                    print(f"Upload successful. Analysis ID: {analysis_id}")
                    if file_hash:
                        print(f"File SHA-256: {file_hash}")
                    return analysis_id, file_hash, None

            except Exception as e:
                print(f"Error parsing upload response: {e}")
                return None

        elif response.status_code == 409:
            # File already exists in VirusTotal database
            print("File already exists in VirusTotal database")
            print("Note: This should not happen since we check hash first")
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
        """Extract file hash from response data"""
        # Try multiple possible locations
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

        max_attempts = 30  # 5 minutes max
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
                        elif (attempt + 1) % 3 == 0:  # Update every 30 seconds
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

                # Get results
                results = attributes.get('results', {})
                if not results:
                    results = attributes.get('last_analysis_results', {})

                # Get stats
                stats = attributes.get('stats', {})
                if not stats:
                    stats = attributes.get('last_analysis_stats', {})
                if not stats and results:
                    stats = self._calculate_stats_from_results(results)

                # Get last analysis date - check multiple possible locations
                last_analysis_date = "Not available"

                # Check for timestamp in various possible locations
                date_fields = ['last_analysis_date', 'last_modification_date',
                               'first_submission_date', 'last_submission_date']

                for field in date_fields:
                    if field in attributes:
                        timestamp = attributes[field]
                        if timestamp:
                            try:
                                import datetime
                                # Convert UNIX timestamp to readable date
                                last_analysis_date = datetime.datetime.fromtimestamp(
                                    int(timestamp)
                                ).strftime('%Y-%m-%d %H:%M:%S Local time')
                                break
                            except:
                                # If conversion fails, show raw value
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

                    # Show top detections
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

    # Determine archive type
    archive_ext = os.path.splitext(archive_path)[1].lower()
    supported_extensions = ['.zip', '.7z', '.rar']

    if archive_ext not in supported_extensions:
        print(f"Unsupported archive format: {archive_ext}")
        print(f"Supported formats: {', '.join(supported_extensions)}")
        return None

    # Create extraction directory
    if extract_dir is None:
        extract_dir = tempfile.mkdtemp(prefix="vt_extract_")
        is_temp = True
    else:
        os.makedirs(extract_dir, exist_ok=True)
        is_temp = False

    print(f"\nExtracting {archive_ext.upper()} archive...")
    print(f"Destination: {extract_dir}")

    try:
        # Extract using 7z
        result = subprocess.run(
            ['7z', 'x', archive_path, f'-o{extract_dir}', '-y'],
            capture_output=True,
            text=True,
            check=False,
            timeout=60  # 60 second timeout for extraction
        )

        if result.returncode == 0:
            # List extracted files
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

                # Show file list
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
                # Clean up empty temp directory
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
        description='Upload files to VirusTotal with mandatory safety checks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SAFETY POLICY:
• Files are ALWAYS scanned before any extraction
• Extraction is BLOCKED if ANY threats are detected
• No force-extract option exists for safety

Examples:
  %(prog)s YOUR_API_KEY document.pdf
  %(prog)s YOUR_API_KEY archive.zip --extract-to ./output
        """
    )

    parser.add_argument('api_key', help='VirusTotal API key')
    parser.add_argument('file', help='File to scan')
    parser.add_argument('--extract-to', metavar='DIRECTORY',
                        help='Extract archive to this directory (only if file is safe)')

    args = parser.parse_args()

    # Check if file exists
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found!")
        sys.exit(1)

    # Check file size (VirusTotal has limits)
    file_size = os.path.getsize(args.file)
    if file_size > 650 * 1024 * 1024:  # 650MB VirusTotal limit
        print(f"Error: File too large ({format_bytes(file_size)})")
        print("VirusTotal maximum file size is 650MB")
        sys.exit(1)

    # Initialize scanner
    scanner = VirusTotalScanner(args.api_key)

    # File information
    file_ext = os.path.splitext(args.file)[1].lower()
    is_archive = file_ext in ['.zip', '.7z', '.rar']

    print(f"File: {os.path.basename(args.file)}")
    print(f"Size: {format_bytes(file_size)}")

    if file_size > scanner.large_file_threshold:
        print(f"Type: Large file (>32MB)")
    elif is_archive:
        print(f"Type: {file_ext.upper()} Archive")
        if args.extract_to:
            print(f"Extract to: {args.extract_to}")
    else:
        print(f"Type: Regular file")

    print("\n" + "="*60)

    # Step 1: Scan the file (check existing first, upload if needed)
    file_hash, analysis_data, is_existing = scanner.scan_file(args.file)

    if not analysis_data:
        print("Failed to get analysis results")
        sys.exit(1)

    if is_existing:
        print("\nNote: Using existing analysis from VirusTotal database")

    # Step 2: Display results and check safety
    total_detections = scanner.display_results(analysis_data, file_hash)

    # Step 3: Handle extraction based on safety
    if is_archive and args.extract_to:
        print("\n" + "="*60)
        print("ARCHIVE EXTRACTION")
        print("="*60)

        if total_detections > 0:
            # UNSAFE - BLOCK EXTRACTION
            print_warning_box(f"""
EXTRACTION BLOCKED!
This archive has {total_detections} threat detection(s).

File SHA-256: {file_hash}

SAFETY ACTION:
• Archive will NOT be extracted
• Consider deleting this file
• Do not attempt to extract manually
• Handle with extreme caution
            """)

            # Show recommendations
            print("Recommended actions:")
            print("1. Delete the file immediately")
            print("2. If needed for analysis, use a sandboxed VM")
            print("3. Do not open or execute any contents")

        else:
            # SAFE - Allow extraction
            print("Archive is clean - Safe to extract")
            if file_hash:
                print(f"File SHA-256: {file_hash}")

            if confirm_action("Proceed with extraction?"):
                extract_dir = extract_archive(args.file, args.extract_to)
                if extract_dir:
                    print(f"\nArchive successfully extracted to: {
                          extract_dir}")
                else:
                    print("\nExtraction failed")
            else:
                print("Extraction cancelled by user")

    elif is_archive and not args.extract_to:
        # Archive but no extraction requested
        if total_detections > 0:
            print_warning_box(f"""
WARNING: UNSAFE ARCHIVE DETECTED
This file has {total_detections} threat detection(s).

File SHA-256: {file_hash}

Recommendation: Delete this file immediately.
            """)
        else:
            if file_hash:
                print(f"\nFile SHA-256: {file_hash}")
            print("Note: Archive is clean but not extracted")
            print("Use --extract-to DIR to extract contents")

    else:
        # Regular file scan
        if total_detections > 0:
            print_warning_box(f"""
WARNING: UNSAFE FILE DETECTED
This file has {total_detections} threat detection(s).

File SHA-256: {file_hash}

Recommendation: Delete this file immediately.
            """)
        elif file_hash:
            print(f"\nFile SHA-256: {file_hash}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
