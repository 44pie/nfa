# NFARun - Multi-threaded NFA Scanner

**NFARun** is a high-performance, multi-threaded runner for NFA (NucleiFuzzer + Arjun) - a comprehensive web vulnerability scanner that combines URL collection, validation, and parameter discovery.

```
 .S_sSSs      sSSs   .S_SSSs    
.SS~YS%%b    d%%SP  .SS~SSSSS   
S%S   `S%b  d%S'    S%S   SSSS  
S%S    S%S  S%S     S%S    S%S  
S%S    S&S  S&S     S%S SSSS%S  
S&S    S&S  S&S_Ss  S&S  SSS%S  
S&S    S&S  S&S~SP  S&S    S&S  
S&S    S&S  S&S     S&S    S&S  
S*S    S*S  S*b     S*S    S&S  
S*S    S*S  S*S     S*S    S*S  
S*S    S*S  S*S     S*S    S*S  
S*S    SSS  S*S     SSS    S*S  
SP          SP             SP   
Y           Y              Y    

NFA - forked from NucleiFuzzer + Arjun Parameter Discovery
```

---

## 🚀 Features

- **Multi-threaded Execution** - Scan multiple domains in parallel with configurable workers
- **Real-time Statistics** - Live monitoring of URL collection, validation, and parameter discovery
- **Comprehensive URL Collection** - Uses 5 tools (ParamSpider, waybackurls, gauplus, hakrawler, katana)
- **Live URL Validation** - httpx validation with multiple status codes
- **Parameter Discovery** - Arjun integration for finding hidden parameters
- **Automatic Cleanup** - Removes temporary files, keeps only final results
- **No Timeouts** - Runs until completion for maximum results

---

## 📋 Components

### `nfa.sh`
Core scanning script that orchestrates the vulnerability assessment pipeline:
- URL collection from multiple sources
- Deduplication and filtering
- Live URL validation
- Parameter discovery with Arjun
- Optional Nuclei vulnerability scanning

### `nfarun.py`
Multi-threaded runner that parallelizes `nfa.sh` execution:
- Queue-based domain processing
- Real-time file monitoring
- Live statistics display
- Worker management
- Automatic result aggregation

---

## 🔧 Installation

### Prerequisites

**Required Tools:**
```bash
# Go tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/bp0lr/gauplus@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python tools
pip3 install arjun uro requests

# Clone ParamSpider
git clone https://github.com/0xKayala/ParamSpider ~/ParamSpider
```

### Setup

```bash
# Clone this repository
git clone https://github.com/yourusername/nfarun.git
cd nfarun

# Make scripts executable
chmod +x nfa.sh nfarun.py

# Verify installation
./nfarun.py --help
```

---

## 💻 Usage

### Basic Usage

```bash
# Scan domains from a file with 7 parallel workers
python3 nfarun.py -l domains.txt -o results -w 7
```

### Command Options

```
nfarun.py [-h] -l LIST [-w WORKERS] -o OUTPUT

Required:
  -l, --list LIST       File containing domains (one per line)
  -o, --output OUTPUT   Output directory for results

Optional:
  -w, --workers N       Number of parallel workers (default: 4)
  -h, --help           Show help message
```

### Examples

```bash
# 4 workers (default)
python3 nfarun.py -l targets.txt -o scan1

# 8 workers for faster scanning
python3 nfarun.py -l domains.txt -w 8 -o scan2

# Single domain in a file
echo "example.com" > domain.txt
python3 nfarun.py -l domain.txt -o results
```

---

## 📊 Real-time Display

```
NFA - forked from NucleiFuzzer + Arjun Parameter Discovery

[+] Total: 28 | Completed: 5 | Failed: 0 | In Queue: 16

==========================================================================================
Worker   Domain                                             Raw        Validated    Arjun   
==========================================================================================
W1       example.com                                        1205       234          12      
W2       test.com                                           890        156          8       
W3       another.com                                        450        89           3       
W4       sample.com                                         2341       478          23      
W5       demo.com                                           120        34           2       
W6       -                                                  0          0            0       
W7       -                                                  0          0            0       
==========================================================================================
```

**Columns:**
- **Raw** - Total URLs collected from all sources
- **Validated** - Live URLs verified by httpx
- **Arjun** - Parameters discovered by Arjun

Updates every 2 seconds in real-time!

---

## 📁 Output Structure

```
results/
├── example.com/
│   ├── example.com_validated.txt    # Live URLs (final)
│   ├── example.com_arjun.txt        # Discovered parameters (final)
│   └── nfa.log                      # Execution log
├── test.com/
│   ├── test.com_validated.txt
│   ├── test.com_arjun.txt
│   └── nfa.log
└── another.com/
    └── ...
```

**Note:** Temporary files (`*_raw.txt`, `*_dedup.txt`) are automatically cleaned up after completion.

---

## 🔍 How It Works

### Pipeline Stages

1. **URL Collection**
   - ParamSpider - Crawls and extracts parameters
   - waybackurls - Fetches from Wayback Machine
   - gauplus - Collects from Common Crawl
   - hakrawler - Web crawler
   - katana - Fast crawler

2. **Deduplication**
   - `uro` removes duplicate URLs
   - Filters by patterns

3. **Validation**
   - `httpx` checks live URLs
   - Status codes: 200, 204, 301, 302, 401, 403, 405, 500, 502, 503, 504

4. **Parameter Discovery**
   - `Arjun` scans for hidden parameters
   - GET method with 50 threads

5. **Results**
   - Final validated URLs saved
   - Discovered parameters logged
   - Cleanup of temporary files

### Multi-threading Architecture

```
Main Thread
├── Worker 1 → Domain Queue → nfa.sh → Results
├── Worker 2 → Domain Queue → nfa.sh → Results
├── Worker 3 → Domain Queue → nfa.sh → Results
├── ...
├── Worker N → Domain Queue → nfa.sh → Results
└── Stats Updater → Real-time Monitoring
```

Each worker:
1. Takes domain from queue
2. Runs `nfa.sh` with full pipeline
3. Monitors file creation in real-time
4. Updates statistics
5. Cleans up temporary files
6. Marks domain as completed
7. Takes next domain

---

## ⚙️ Configuration

### Adjusting Workers

Choose worker count based on:
- **CPU cores** - More cores = more workers
- **Network bandwidth** - Higher bandwidth = more workers
- **API rate limits** - Some tools call external APIs

**Recommended:**
- 4-7 workers for typical setups
- 8-12 workers for high-performance servers
- 1-3 workers for rate-limited environments

### Customizing nfa.sh

Edit `nfa.sh` to:
- Add/remove URL collection tools
- Adjust httpx status codes
- Configure Arjun parameters
- Enable Nuclei scanning (disabled by default)

---

## 🐛 Troubleshooting

### Issue: "command not found: httpx"

**Solution:** Make sure Go bin is in PATH
```bash
export PATH="$HOME/go/bin:$PATH"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Issue: Wrong httpx (Python version)

**Solution:** Remove Python httpx or ensure Go version has priority
```bash
mv ~/.pythonlibs/bin/httpx ~/.pythonlibs/bin/httpx-python
```

### Issue: Process hangs on waybackurls/gauplus

**Cause:** External APIs may be slow or rate-limited

**Solution:** Wait for completion (no timeouts by design for maximum results)

### Issue: No parameters found

This is normal! Many domains don't have discoverable parameters. Check:
- `*_validated.txt` - Were any URLs validated?
- `nfa.log` - Are there errors?

---

## 📈 Performance Tips

1. **Start with fewer workers** - Test with 4 workers first
2. **Monitor system resources** - CPU, memory, network
3. **Large domain lists** - Split into batches if needed
4. **External APIs** - waybackurls/gauplus depend on external services

---

## 🙏 Credits

- **NucleiFuzzer** by Satya Prakash (0xKayala)
- **Arjun** - HTTP parameter discovery tool
- **ProjectDiscovery** - httpx, katana, nuclei
- **Community Tools** - waybackurls, gauplus, hakrawler, ParamSpider

---

## 📄 License

This project is a fork and enhancement of NucleiFuzzer. Please respect the original licenses of all integrated tools.

---

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always obtain proper permission before scanning any domain you don't own.

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation in the repository

---

**NFARun v1.2.1** - Multi-threaded vulnerability scanning made simple

🟢 Real-time stats | 🚫 No timeouts | 📊 File monitoring | ⚡ Efficient | 💜 Purple banner
