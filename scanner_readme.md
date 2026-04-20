# White Cell Port Scanner

A fast and lightweight Go-based port scanner for the White Cell cybersecurity CLI tool. This scanner uses goroutines to concurrently scan ports and perform banner grabbing to identify services.

## Features

- Concurrent port scanning using goroutines
- Fast banner grabbing to identify service versions
- Lightweight and efficient
- Designed for continuous monitoring as a background agent
- Outputs results in JSON format

## Ports Scanned

The scanner checks the following commonly targeted ports:
- 21: FTP
- 22: SSH
- 80: HTTP
- 443: HTTPS
- 3306: MySQL
- 8080: HTTP Alternative

## Requirements

- Go 1.16 or higher

## Compilation

To compile the scanner:

```bash
go build -o scanner scanner.go
```

For cross-compilation to different platforms:

```bash
# For Linux
GOOS=linux GOARCH=amd64 go build -o scanner_linux scanner.go

# For Windows
GOOS=windows GOARCH=amd64 go build -o scanner_windows.exe scanner.go

# For macOS
GOOS=darwin GOARCH=amd64 go build -o scanner_mac scanner.go
```

## Usage

```bash
./scanner <domain_or_ip>
```

Example:

```bash
./scanner google.com
# Output: {"target":"google.com","open_ports":[80,443],"banners":{"80":"HTTP","443":"HTTPS"}}
```

```bash
./scanner 192.168.1.1
# Output: {"target":"192.168.1.1","open_ports":[22,80,443],"banners":{"22":"SSH","80":"Apache 2.4.41","443":"nginx"}}
```

## Integration with Python

You can call the scanner from your Python application using subprocess:

```python
import subprocess
import json

def scan_target(target):
    try:
        result = subprocess.run(['./scanner', target], 
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            print(f"Scanner error: {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        print("Scanner timed out")
        return None
    except Exception as e:
        print(f"Error running scanner: {e}")
        return None

# Example usage
scan_result = scan_target('example.com')
if scan_result:
    print(scan_result)
```

## Performance

The scanner is optimized for speed and efficiency:
- Concurrent scanning using goroutines
- Short timeouts to prevent hanging on closed ports
- Minimal memory footprint
- Designed for background operation

## Security Considerations

- Only scan targets you own or have explicit permission to scan
- Be aware of legal implications of port scanning in your jurisdiction
- The scanner should be deployed with appropriate network access restrictions