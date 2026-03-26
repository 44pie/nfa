#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import threading
import queue
from pathlib import Path
import re
import time

C7 = '\033[38;5;201m'
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

class FileMonitor:
    """Monitors file and counts new lines efficiently"""
    def __init__(self, filepath):
        self.filepath = filepath
        self.offset = 0
        self.count = 0
        
    def update_count(self):
        try:
            if not os.path.exists(self.filepath):
                return self.count
            with open(self.filepath, 'r') as f:
                f.seek(self.offset)
                new_lines = sum(1 for line in f if line.strip())
                self.count += new_lines
                self.offset = f.tell()
        except Exception:
            pass
        return self.count
        
    def reset(self):
        self.offset = 0
        self.count = 0

class WorkerStats:
    def __init__(self, worker_id):
        self.worker_id = worker_id
        self.domain = "Idle"
        self.output_dir = None
        self.raw_monitor = None
        self.validated_monitor = None
        self.arjun_monitor = None
        self.raw = 0
        self.validated = 0
        self.arjun = 0
        self.is_working = False
        
    def reset_for_domain(self, domain, output_dir):
        self.domain = domain
        self.output_dir = output_dir
        self.raw = 0
        self.validated = 0
        self.arjun = 0
        self.is_working = True
        self.raw_monitor = FileMonitor(os.path.join(output_dir, f"{domain}_raw.txt"))
        self.validated_monitor = FileMonitor(os.path.join(output_dir, f"{domain}_validated.txt"))
        self.arjun_monitor = FileMonitor(os.path.join(output_dir, f"{domain}_arjun.txt"))
        
    def update_realtime_stats(self):
        if not self.is_working:
            return
        if self.raw_monitor:
            self.raw = self.raw_monitor.update_count()
        if self.validated_monitor:
            self.validated = self.validated_monitor.update_count()
        if self.arjun_monitor:
            self.arjun = self.arjun_monitor.update_count()
        
    def set_idle(self):
        self.domain = "Idle"
        self.is_working = False
        self.raw_monitor = None
        self.validated_monitor = None
        self.arjun_monitor = None
        self.raw = 0
        self.validated = 0
        self.arjun = 0

class NFARunner:
    def __init__(self, domains_file, num_workers, output_folder, resolvers=None, use_arjun=False):
        self.domains_file = domains_file
        self.num_workers = num_workers
        self.output_folder = output_folder
        self.resolvers = resolvers
        self.use_arjun = use_arjun
        self.domain_queue = queue.Queue()
        self.worker_stats = {}
        self.lock = threading.Lock()
        self.total_domains = 0
        self.completed_domains = 0
        self.failed_domains = 0
        self.stop_event = threading.Event()
        
        for i in range(1, num_workers + 1):
            self.worker_stats[i] = WorkerStats(i)
        
    def print_banner(self):
        banner = [
            " .S_sSSs      sSSs   .S_SSSs    ",
            ".SS~YS%%b    d%%SP  .SS~SSSSS   ",
            "S%S   `S%b  d%S'    S%S   SSSS  ",
            "S%S    S%S  S%S     S%S    S%S  ",
            "S%S    S&S  S&S     S%S SSSS%S  ",
            "S&S    S&S  S&S_Ss  S&S  SSS%S  ",
            "S&S    S&S  S&S~SP  S&S    S&S  ",
            "S&S    S&S  S&S     S&S    S&S  ",
            "S*S    S*S  S*b     S*S    S&S  ",
            "S*S    S*S  S*S     S*S    S*S  ",
            "S*S    S*S  S*S     S*S    S*S  ",
            "S*S    SSS  S*S     SSS    S*S  ",
            "SP          SP             SP   ",
            "Y           Y              Y    "
        ]
        for line in banner:
            print(f"{CYAN}{line}{RESET}")
        print()
        print(f"{CYAN}NFA - forked from NucleiFuzzer + Arjun Parameter Discovery{RESET}")
        print()
        
    def load_domains(self):
        try:
            with open(self.domains_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            self.total_domains = len(domains)
            return domains
        except FileNotFoundError:
            print(f"{RED}[!] Error: File {self.domains_file} not found{RESET}")
            sys.exit(1)
            
    def create_output_folder(self):
        Path(self.output_folder).mkdir(parents=True, exist_ok=True)
        
    def parse_nfa_output(self, line, stats):
        pass
                
    def print_stats_table(self):
        with self.lock:
            for worker_id in self.worker_stats.keys():
                self.worker_stats[worker_id].update_realtime_stats()
            
            os.system('clear')
            self.print_banner()
        
            print(f"[+] Total: {self.total_domains} | Completed: {self.completed_domains} | Failed: {self.failed_domains} | In Queue: {self.domain_queue.qsize()}")
            print()
            print('='*90)
            print(f"{'Worker':<8} {'Domain':<50} {'Raw':<10} {'Validated':<12} {'Arjun':<8}")
            print('='*90)
            
            for worker_id in sorted(self.worker_stats.keys()):
                stats = self.worker_stats[worker_id]
                domain_display = stats.domain if stats.domain != "Idle" else "-"
                print(f"W{worker_id:<7} {domain_display:<50} {stats.raw:<10} {stats.validated:<12} {stats.arjun:<8}")
            
            print('='*90)
            print()
            
    def worker_thread(self, worker_id):
        stats = self.worker_stats[worker_id]
        
        while not self.stop_event.is_set():
            try:
                domain = self.domain_queue.get(timeout=1)
            except queue.Empty:
                with self.lock:
                    stats.set_idle()
                continue
            
            domain_output = os.path.join(self.output_folder, domain)
            
            with self.lock:
                stats.reset_for_domain(domain, domain_output)
            
            env = os.environ.copy()
            go_bin = os.path.expanduser('~/go/bin')
            local_bin = os.path.expanduser('~/.local/bin')
            path_parts = env.get('PATH', '').split(':')
            path_parts = [p for p in path_parts if '.pythonlibs' not in p]
            clean_path = ':'.join(path_parts)
            env['PATH'] = f"{go_bin}:{local_bin}:{clean_path}"
            
            # Build command - nuclei is on by default in nfa.sh
            nfa_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nfa.sh")
            cmd = ["bash", nfa_script, "-d", domain, "-o", domain_output, "-k"]
            if self.use_arjun:
                cmd.append("--arjun")
            if self.resolvers:
                cmd.extend(["-r", self.resolvers])
            
            success = False
            error_lines = []
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=env
                )
                
                if process.stdout:
                    for line in process.stdout:
                        with self.lock:
                            self.parse_nfa_output(line, stats)
                        if "error" in line.lower() or "failed" in line.lower():
                            error_lines.append(line.strip())
                
                process.wait()
                
                if process.returncode == 0:
                    success = True
                elif error_lines:
                    print(f"{RED}[W{worker_id}] Errors for {domain}:{RESET}")
                    for err_line in error_lines[:3]:
                        print(f"{RED}  {err_line[:100]}{RESET}")
                    
            except Exception as e:
                print(f"{RED}[W{worker_id}] Exception for {domain}: {str(e)}{RESET}")
            
            with self.lock:
                stats.update_realtime_stats()
                
                if success:
                    self.completed_domains += 1
                else:
                    self.failed_domains += 1
                
                try:
                    raw_file = os.path.join(domain_output, f"{domain}_raw.txt")
                    dedup_file = os.path.join(domain_output, f"{domain}_dedup.txt")
                    if os.path.exists(raw_file):
                        os.remove(raw_file)
                    if os.path.exists(dedup_file):
                        os.remove(dedup_file)
                except Exception:
                    pass
                    
                stats.set_idle()
                
            self.domain_queue.task_done()
            
    def stats_updater_thread(self):
        while not self.stop_event.is_set():
            self.print_stats_table()
            time.sleep(2)
            
    def run(self):
        print("\033[2J\033[H", end="")
        self.print_banner()
        
        print(f"{CYAN}[*] Loading domains from {self.domains_file}...{RESET}")
        domains = self.load_domains()
        
        print(f"{GREEN}[+] Loaded {len(domains)} domains{RESET}")
        print(f"{CYAN}[*] Workers:  {self.num_workers}{RESET}")
        print(f"{CYAN}[*] Output:   {self.output_folder}{RESET}")
        print(f"{CYAN}[*] Nuclei:   ON (default){RESET}")
        print(f"{CYAN}[*] Arjun:    {'ON' if self.use_arjun else 'OFF'}{RESET}")
        print(f"{CYAN}[*] Resolvers: {self.resolvers if self.resolvers else 'none'}{RESET}")
        
        self.create_output_folder()
        
        for domain in domains:
            self.domain_queue.put(domain)
            
        print(f"\n{YELLOW}[*] Starting NFARun with {self.num_workers} workers...{RESET}\n")
        time.sleep(2)
        
        worker_threads = []
        for i in range(1, self.num_workers + 1):
            t = threading.Thread(target=self.worker_thread, args=(i,), daemon=True)
            t.start()
            worker_threads.append(t)
            
        stats_thread = threading.Thread(target=self.stats_updater_thread, daemon=True)
        stats_thread.start()
        
        try:
            self.domain_queue.join()
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
            self.stop_event.set()
            sys.exit(1)
            
        self.stop_event.set()
        
        for t in worker_threads:
            t.join(timeout=2)
            
        self.print_stats_table()
        
        print(f"{GREEN}[+] All domains processed!{RESET}")
        print(f"{CYAN}[*] Total: {self.total_domains} | Completed: {self.completed_domains} | Failed: {self.failed_domains}{RESET}\n")

def main():
    parser = argparse.ArgumentParser(
        description="NFARun - Multi-threaded NFA Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # nuclei only, 4 workers
  ./nfarun.py -l domains.txt -w 4 -o results/

  # nuclei + custom resolvers, 8 workers
  ./nfarun.py -l domains.txt -w 8 -o results/ -r /path/to/resolvers.txt

  # nuclei + arjun, 4 workers
  ./nfarun.py -l domains.txt -w 4 -o results/ --arjun

  # nuclei + arjun + resolvers
  ./nfarun.py -l domains.txt -w 4 -o results/ --arjun -r resolvers.txt
        """
    )
    
    parser.add_argument('-l', '--list', required=True, help='File with list of domains (one per line)')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of parallel workers (default: 4)')
    parser.add_argument('-o', '--output', required=True, help='Output folder to save results')
    parser.add_argument('-r', '--resolvers', default=None, help='Path to resolvers file for Nuclei')
    parser.add_argument('--arjun', action='store_true', help='Enable Arjun parameter discovery (disabled by default)')
    
    args = parser.parse_args()
    
    if not os.path.isfile(args.list):
        print(f"{RED}[!] Error: File {args.list} does not exist{RESET}")
        sys.exit(1)
    
    if args.resolvers and not os.path.isfile(args.resolvers):
        print(f"{RED}[!] Error: Resolvers file {args.resolvers} does not exist{RESET}")
        sys.exit(1)
        
    runner = NFARunner(args.list, args.workers, args.output, resolvers=args.resolvers, use_arjun=args.arjun)
    
    try:
        runner.run()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
