#!/bin/bash

# ANSI color codes (256-color gradient)
C1='\033[38;5;196m'  # Red
C2='\033[38;5;202m'  # Orange-Red
C3='\033[38;5;226m'  # Yellow
C4='\033[38;5;46m'   # Green
C5='\033[38;5;51m'   # Cyan
C6='\033[38;5;21m'   # Blue
C7='\033[38;5;201m'  # Magenta
CYAN='\033[96m'
RESET='\033[0m'

# ASCII art (Purple banner)
banner=(
""
" .S_sSSs      sSSs   .S_SSSs    "
".SS~YS%%b    d%%SP  .SS~SSSSS   "
"S%S   \`S%b  d%S'    S%S   SSSS  "
"S%S    S%S  S%S     S%S    S%S  "
"S%S    S&S  S&S     S%S SSSS%S  "
"S&S    S&S  S&S_Ss  S&S  SSS%S  "
"S&S    S&S  S&S~SP  S&S    S&S  "
"S&S    S&S  S&S     S&S    S&S  "
"S*S    S*S  S*b     S*S    S&S  "
"S*S    S*S  S*S     S*S    S*S  "
"S*S    S*S  S*S     S*S    S*S  "
"S*S    SSS  S*S     SSS    S*S  "
"SP          SP             SP   "
"Y           Y              Y    "
)

for line in "${banner[@]}"; do
    echo -e "${CYAN}${line}${RESET}"
done

echo ""
echo -e "${CYAN}NFA - forked from NucleiFuzzer + Arjun Parameter Discovery${RESET}"
echo ""

# Default settings
OUTPUT_FOLDER="./output"
HOME_DIR=$(eval echo ~"$USER")
EXCLUDED_EXTENSIONS="png,jpg,gif,jpeg,swf,woff,svg,pdf,json,css,js,webp,woff,woff2,eot,ttf,otf,mp4,txt"
LOG_FILE=""
VERBOSE=false
KEEP_TEMP=false
RATE_LIMIT=50
RESOLVERS=""
RESULT_FILE=""
RUN_NUCLEI=true
RUN_ARJUN=false

# Help menu
display_help() {
    echo -e "NFA: NFCrawl with Arjun - Advanced Parameter Discovery & Vulnerability Scanning\n"
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help              Display this help menu"
    echo "  -d, --domain <domain>   Scan a single domain"
    echo "  -f, --file <filename>   Scan multiple domains/URLs from a file"
    echo "  -o, --output <folder>   Output folder (default: ./output)"
    echo "  -t, --templates <path>  Custom Nuclei templates directory"
    echo "  --arjun                 Enable Arjun parameter discovery (disabled by default)"
    echo "  --no-nuclei             Disable Nuclei vulnerability scanning"
    echo "  -r, --resolvers <file>  Path to resolvers file for Nuclei"
    echo "  --rate <limit>          Set rate limit for Nuclei (default: 50)"
    echo "  -v, --verbose           Enable verbose output (logs to terminal)"
    echo "  -k, --keep-temp         Keep temporary files after execution"
    exit 0
}

# Log function
log() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    if [ "$VERBOSE" = true ] || [ "$level" = "ERROR" ]; then
        echo -e "${YELLOW}[$level]${RESET} $message"
    fi
}

# Check prerequisites
check_prerequisite() {
    local tool="$1"
    local install_command="$2"
    if ! command -v "$tool" &> /dev/null; then
        log "INFO" "Installing $tool..."
        if ! eval "$install_command"; then
            log "ERROR" "Failed to install $tool. Exiting."
            exit 1
        fi
        if [ "$tool" = "uro" ] && [ -f "$HOME/.local/bin/uro" ]; then
            export PATH="$HOME/.local/bin:$PATH"
            log "INFO" "Added $HOME/.local/bin to PATH."
        fi
    fi
}

# Check Python module
check_python_module() {
    local module="$1"
    if ! python3 -c "import $module" &>/dev/null; then
        log "INFO" "Installing Python module: $module"
        pip3 install --break-system-packages "$module" || log "ERROR" "Failed to install $module"
    fi
}

# Clone repositories
clone_repo() {
    local repo_url="$1"
    local target_dir="$2"
    if [ ! -d "$target_dir" ]; then
        log "INFO" "Cloning $repo_url to $target_dir..."
        if ! git clone "$repo_url" "$target_dir"; then
            log "ERROR" "Failed to clone $repo_url. Exiting."
            exit 1
        fi
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) display_help ;;
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -f|--file) FILENAME="$2"; shift 2 ;;
        -o|--output) OUTPUT_FOLDER="$2"; shift 2 ;;
        -t|--templates) TEMPLATE_DIR="$2"; shift 2 ;;
        --arjun) RUN_ARJUN=true; shift ;;
        --no-nuclei) RUN_NUCLEI=false; shift ;;
        -r|--resolvers) RESOLVERS="$2"; shift 2 ;;
        --rate) RATE_LIMIT="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -k|--keep-temp) KEEP_TEMP=true; shift ;;
        *) log "ERROR" "Unknown option: $1"; display_help ;;
    esac
done

# Validate input
if [ -z "$DOMAIN" ] && [ -z "$FILENAME" ]; then
    log "ERROR" "Please provide a domain (-d) or file (-f)."
    display_help
fi

# Validate resolvers file if provided
if [ -n "$RESOLVERS" ] && [ ! -f "$RESOLVERS" ]; then
    echo "ERROR: Resolvers file not found: $RESOLVERS"
    exit 1
fi

# Setup
mkdir -p "$OUTPUT_FOLDER"
LOG_FILE="$OUTPUT_FOLDER/nfa.log"
echo "" > "$LOG_FILE"
TEMPLATE_DIR=${TEMPLATE_DIR:-"$HOME_DIR/nuclei-templates"}

# Suggest venv usage
if [[ "$VIRTUAL_ENV" == "" ]]; then
    log "WARNING" "You are not using a Python virtual environment. It is recommended."
fi

# Ensure Go bin path is in PATH
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    export PATH="$HOME/go/bin:$PATH"
    log "INFO" "Added $HOME/go/bin to PATH."
fi

# Dependency installation
check_prerequisite "python3" "sudo apt install -y python3"
check_prerequisite "pip3" "sudo apt install -y python3-pip"
check_python_module "requests"
check_python_module "urllib3"
check_prerequisite "httpx" "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_prerequisite "uro" "pip3 install --break-system-packages uro"
check_prerequisite "katana" "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
check_prerequisite "waybackurls" "go install github.com/tomnomnom/waybackurls@latest"
check_prerequisite "gauplus" "go install github.com/bp0lr/gauplus@latest"
check_prerequisite "hakrawler" "go install github.com/hakluke/hakrawler@latest"
clone_repo "https://github.com/0xKayala/ParamSpider" "$HOME_DIR/ParamSpider"

# Arjun setup only if enabled
if [ "$RUN_ARJUN" = true ]; then
    clone_repo "https://github.com/s0md3v/Arjun.git" "$HOME_DIR/Arjun"
    if ! command -v arjun &> /dev/null; then
        if [ -f "$HOME_DIR/Arjun/arjun.py" ]; then
            mkdir -p "$HOME/.local/bin"
            echo '#!/bin/bash' > "$HOME/.local/bin/arjun"
            echo "python3 $HOME_DIR/Arjun/arjun.py \"\$@\"" >> "$HOME/.local/bin/arjun"
            chmod +x "$HOME/.local/bin/arjun"
            export PATH="$HOME/.local/bin:$PATH"
            log "INFO" "Created arjun wrapper in $HOME/.local/bin/arjun"
        fi
    fi
fi

# Nuclei setup
if [ "$RUN_NUCLEI" = true ]; then
    check_prerequisite "nuclei" "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    clone_repo "https://github.com/projectdiscovery/nuclei-templates.git" "$HOME_DIR/nuclei-templates"
fi

# Validate input format
validate_input() {
    local input="$1"
    if [[ "$input" =~ ^https?://[a-zA-Z0-9.-]+(/.*)?$ ]]; then
        echo "$input"
    elif [[ "$input" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo "http://$input"
    else
        log "ERROR" "Invalid input: $input"
        return 1
    fi
}

# URL collection
collect_urls() {
    local target="$1"
    local output_file="$2"
    local validated_target=$(validate_input "$target") || return 1

    log "INFO" "Starting URL collection for $validated_target..."

    echo -e "${GREEN}Collecting URLs for $validated_target...${RESET} using ParamSpider"
    python3 "$HOME_DIR/ParamSpider/paramspider.py" -d "$target" --exclude "$EXCLUDED_EXTENSIONS" --level high --quiet -o "$output_file.tmp" &&
    cat "$output_file.tmp" >> "$output_file" && rm -f "$output_file.tmp"

    echo -e "${GREEN}Collecting URLs for $validated_target...${RESET} using Waybackurls"
    echo "$validated_target" | waybackurls >> "$output_file"

    echo -e "${GREEN}Collecting URLs for $validated_target...${RESET} using Gauplus"
    echo "$validated_target" | gauplus -subs -b "$EXCLUDED_EXTENSIONS" >> "$output_file"

    echo -e "${GREEN}Collecting URLs for $validated_target...${RESET} using Hakrawler"
    echo "$validated_target" | hakrawler -d 3 -subs -u >> "$output_file"

    echo -e "${GREEN}Collecting URLs for $validated_target...${RESET} using Katana"
    echo "$validated_target" | katana -d 3 -silent -rl 10 >> "$output_file"
}

# Validate & deduplicate URLs
validate_urls() {
    local input_file="$1"
    local output_file="$2"
    if [ ! -s "$input_file" ]; then
        log "ERROR" "No URLs found in $input_file."
        exit 1
    fi
    echo -e "${GREEN}Deduplicating URLs from $input_file...${RESET}"
    sort -u "$input_file" | uro > "$output_file"
}

# Validate live URLs with httpx
validate_httpx() {
    local input_file="$1"
    local output_file="$2"
    echo -e "${GREEN}Validating live URLs with httpx...${RESET}"
    httpx -silent -mc 200,204,301,302,401,403,405,500,502,503,504 -l "$input_file" -o "$output_file"
}

# Run Arjun parameter discovery
run_arjun() {
    local input_file="$1"
    local output_file="$2"
    if [ ! -s "$input_file" ]; then
        log "WARNING" "No validated URLs found for Arjun scanning."
        return 0
    fi
    echo -e "${GREEN}Running Arjun parameter discovery...${RESET}"
    log "INFO" "Arjun scanning $input_file..."
    arjun -i "$input_file" -m GET -T 50 -oT "$output_file" 2>&1 | tee -a "$LOG_FILE"
    if [ -s "$output_file" ]; then
        log "INFO" "Arjun results saved to $output_file"
    else
        log "WARNING" "Arjun did not find any parameters."
    fi
}

# Run nuclei
run_nuclei() {
    local url_file="$1"
    echo -e "${GREEN}Running Nuclei vulnerability scan...${RESET}"
    local nuclei_cmd="nuclei -l \"$url_file\" -t \"$TEMPLATE_DIR\" -dast -rl \"$RATE_LIMIT\" -o \"$RESULT_FILE\""
    if [ -n "$RESOLVERS" ]; then
        nuclei_cmd="nuclei -l \"$url_file\" -t \"$TEMPLATE_DIR\" -dast -rl \"$RATE_LIMIT\" -r \"$RESOLVERS\" -o \"$RESULT_FILE\""
    fi
    eval "$nuclei_cmd"
}

# Main logic
if [ -n "$DOMAIN" ]; then
    DOMAIN_RAW="${DOMAIN//[^a-zA-Z0-9.-]/_}"
    RAW_FILE="$OUTPUT_FOLDER/${DOMAIN_RAW}_raw.txt"
    DEDUP_FILE="$OUTPUT_FOLDER/${DOMAIN_RAW}_dedup.txt"
    VALIDATED_FILE="$OUTPUT_FOLDER/${DOMAIN_RAW}_validated.txt"
    ARJUN_FILE="$OUTPUT_FOLDER/${DOMAIN_RAW}_arjun.txt"
    RESULT_FILE="$OUTPUT_FOLDER/${DOMAIN_RAW}_nuclei_results.txt"
    
    collect_urls "$DOMAIN" "$RAW_FILE"
    validate_urls "$RAW_FILE" "$DEDUP_FILE"
    validate_httpx "$DEDUP_FILE" "$VALIDATED_FILE"

    if [ "$RUN_ARJUN" = true ]; then
        run_arjun "$VALIDATED_FILE" "$ARJUN_FILE"
    fi
    
    if [ "$RUN_NUCLEI" = true ]; then
        run_nuclei "$VALIDATED_FILE"
    fi
elif [ -n "$FILENAME" ]; then
    if [ ! -f "$FILENAME" ]; then
        log "ERROR" "File $FILENAME not found."
        exit 1
    fi
    TOTAL_LINES=$(wc -l < "$FILENAME")
    COUNT=0
    RAW_FILE="$OUTPUT_FOLDER/all_raw.txt"
    DEDUP_FILE="$OUTPUT_FOLDER/all_dedup.txt"
    VALIDATED_FILE="$OUTPUT_FOLDER/all_validated.txt"
    ARJUN_FILE="$OUTPUT_FOLDER/all_arjun.txt"
    RESULT_FILE="$OUTPUT_FOLDER/all_nuclei_results.txt"
    echo "" > "$RAW_FILE"
    
    while IFS= read -r line; do
        ((COUNT++))
        echo -e "${YELLOW}[Progress]${RESET} Processing $COUNT/$TOTAL_LINES: $line"
        collect_urls "$line" "$RAW_FILE"
    done < "$FILENAME"
    
    validate_urls "$RAW_FILE" "$DEDUP_FILE"
    validate_httpx "$DEDUP_FILE" "$VALIDATED_FILE"

    if [ "$RUN_ARJUN" = true ]; then
        run_arjun "$VALIDATED_FILE" "$ARJUN_FILE"
    fi
    
    if [ "$RUN_NUCLEI" = true ]; then
        run_nuclei "$VALIDATED_FILE"
    fi
fi

# Cleanup
if [ "$KEEP_TEMP" = false ]; then
    log "INFO" "Cleaning up temporary files..."
    rm -f "$OUTPUT_FOLDER"/*_raw.txt "$OUTPUT_FOLDER"/*_dedup.txt 2>/dev/null
fi

echo -e "${RED}NFA scanning completed!${RESET}"
if [ "$RUN_ARJUN" = true ]; then
    echo -e "${GREEN}→ Arjun results: $ARJUN_FILE${RESET}"
fi
if [ "$RUN_NUCLEI" = true ]; then
    log "INFO" "Nuclei results saved in $RESULT_FILE."
    echo -e "${GREEN}→ Nuclei results: $RESULT_FILE${RESET}"
else
    echo -e "${GREEN}→ Validated URLs: $VALIDATED_FILE${RESET}"
fi
