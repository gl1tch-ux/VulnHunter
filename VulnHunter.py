import uuid
import subprocess
import argparse
import requests
import os
import threading
from queue import Queue
from colorama import Fore, Style
import logging

VERSION = "1.5"

print(f"Vulnerability Scanner - Version: {VERSION}")

print(""" __      __    _       _    _             _            
 \ \    / /   | |     | |  | |           | |           
  \ \  / /   _| |_ __ | |__| |_   _ _ __ | |_ ___ _ __ 
   \ \/ / | | | | '_ \|  __  | | | | '_ \| __/ _ \ '__|
    \  /| |_| | | | | | |  | | |_| | | | | ||  __/ |   
     \/  \__,_|_|_| |_|_|  |_|\__,_|_| |_|\__\___|_|   
                                                       
                                                 By Glitch01     """)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class VulnerabilityScanner:
    def __init__(self, host, payloads_dir, output_file, wordlist, threads):
        self.host = host
        self.payloads_dir = payloads_dir
        self.output_file = output_file
        self.wordlist = wordlist
        self.threads = threads
        self.alive_subdomains = []
        self.fuzzed_params = []
        self.alive_php_files = []
        self.alive_directories = []
        self.results = []
        self.lock = threading.Lock()

    def update_code(self):
        print("[*] Updating code from GitHub repository...")
        try:
            subprocess.run(["git", "pull"], check=True)
            print(Fore.GREEN + "[*] Code updated successfully!" + Style.RESET_ALL)
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"Error updating code: {e}" + Style.RESET_ALL)

    def fuzz_subdomains(self):
        print("[*] Start fuzzing subdomains...")
        subdomain_file = os.path.join(self.payloads_dir, "subs.txt")
        if not os.path.exists(subdomain_file):
            print(Fore.RED + "Error: subs.txt not found!" + Style.RESET_ALL)
            return

        with open(subdomain_file, 'r') as f:
            subdomains = [line.strip() for line in f.readlines()]

        def worker():
            while not subdomain_queue.empty():
                subdomain = subdomain_queue.get()
                for protocol in ["http", "https"]:
                    subdomain_url = f"{protocol}://{subdomain}.{self.host}"
                    try:
                        response = requests.get(subdomain_url, timeout=5)
                        if response.status_code == 200:
                            with self.lock:
                                self.alive_subdomains.append(subdomain_url)
                            print(Fore.GREEN + f"Found active subdomain: {subdomain_url}" + Style.RESET_ALL)
                            break
                    except requests.RequestException:
                        continue
                subdomain_queue.task_done()

        subdomain_queue = Queue()
        for subdomain in subdomains:
            subdomain_queue.put(subdomain)

        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()

        subdomain_queue.join()

def brute_force_directories(self):
    print("[*] Start brute-forcing directories from alive subdomains...")
    dir_file = os.path.join(self.payloads_dir, "dir.txt")
    if not os.path.exists(dir_file):
        print(Fore.RED + "Error: dir.txt not found!" + Style.RESET_ALL)
        return

    with open(dir_file, 'r') as f:
        directories = [line.strip() for line in f.readlines()]

    def worker(subdomain):
        for directory in directories:
            url = f"{subdomain}{directory}"  
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 or (300 <= response.status_code < 400):
                    with self.lock:
                        self.alive_directories.append(url)
                    print(Fore.GREEN + f"Found alive directory: {url}" + Style.RESET_ALL)
            except requests.RequestException:
                continue

    for subdomain in self.alive_subdomains:
        t = threading.Thread(target=worker, args=(subdomain,))
        t.daemon = True
        t.start()

    for t in threading.enumerate():
        if t is not threading.currentThread():
            t.join()

    def brute_force_php_files(self):
        print("[*] Start brute-forcing PHP files from alive subdomains...")
        php_file_list = os.path.join(self.payloads_dir, "php_files.txt")
        if not os.path.exists(php_file_list):
            print(Fore.RED + "Error: php_files.txt not found!" + Style.RESET_ALL)
            return

        with open(php_file_list, 'r') as f:
            php_files = [line.strip() for line in f.readlines()]

        def worker(subdomain):
            for php_file in php_files:
                url = f"{subdomain}{php_file}"
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200 or (300 <= response.status_code < 400):
                        with self.lock:
                            self.alive_php_files.append(url)
                        print(Fore.GREEN + f"Found alive PHP file: {url}" + Style.RESET_ALL)
                except requests.RequestException:
                    continue

        for subdomain in self.alive_subdomains:
            t = threading.Thread(target=worker, args=(subdomain,))
            t.daemon = True
            t.start()

        for t in threading.enumerate():
            if t is not threading.currentThread():
                t.join()

    def fuzz_parameters(self):
        print("[*] Start fuzzing params...")
        param_file = os.path.join(self.payloads_dir, "params.txt")
        
        if not os.path.exists(param_file):
            print(Fore.RED + "Error: params.txt not found!" + Style.RESET_ALL)
            return

        with open(param_file, 'r') as f:
            params = [line.strip() for line in f.readlines()]

        def fuzz_params_for_php_file():
            for php_file in self.alive_php_files:
                for param in params:
                    fuzz_url = f"{php_file}{param}FUZZ"
                    try:
                        response = requests.get(fuzz_url, timeout=5)
                        if response.status_code == 200:
                            with self.lock:
                                self.fuzzed_params.append(fuzz_url)
                            print(Fore.GREEN + f"Working parameter: {fuzz_url}" + Style.RESET_ALL)
                    except requests.RequestException:
                        continue

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=fuzz_params_for_php_file)
            threads.append(t)
            t.start()

        for thread in threads:
            thread.join()

    def scan_vulnerabilities(self):
        print("[*] Starting vulnerability scans...")
        self.scan_sqli()
        self.scan_xss()
        self.scan_rce()
        self.scan_lfi()
        self.scan_rfi()
        self.scan_ssrf()
        self.scan_xxe()

    def scan_sqli(self):
        print("[*] Start scanning for SQL injection vulnerabilities...")
        sqli_file = os.path.join(self.payloads_dir, "SQLi.txt")
        if not os.path.exists(sqli_file):
            print(Fore.RED + "Error: sqli.txt not found!" + Style.RESET_ALL)
            return

        with open(sqli_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]

        def scan_for_sqli(fuzz_url):
            vulnerable = False
            for payload in payloads:
                vuln_url = fuzz_url.replace("FUZZ", payload)
                try:
                    response = requests.get(vuln_url, timeout=5)
                    if "SQL syntax" in response.text or "database error" in response.text:
                        with self.lock:
                            self.results.append(f"[SQL Injection] Vulnerability found: {vuln_url}")
                        print(Fore.GREEN + f"[SQL Injection] Vulnerability found: {vuln_url}" + Style.RESET_ALL)
                        vulnerable = True
                        break
                except requests.RequestException:
                    continue
            if not vulnerable:
                print(Fore.RED + f"[SQL Injection] Not vulnerable: {fuzz_url}" + Style.RESET_ALL)

        threads = []
        for fuzz_url in self.fuzzed_params:
            t = threading.Thread(target=scan_for_sqli, args=(fuzz_url,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

    def scan_xss(self):
        print("[*] Start scanning for XSS vulnerabilities...")
        xss_file = os.path.join(self.payloads_dir, "XSS.txt")
        if not os.path.exists(xss_file):
            print(Fore.RED + "Error: XSS.txt not found!" + Style.RESET_ALL)
            return

        with open(xss_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]

        def scan_for_xss(fuzz_url):
            vulnerable = False
            for payload in payloads:
                vuln_url = fuzz_url.replace("FUZZ", payload)
                try:
                    response = requests.get(vuln_url, timeout=5)
                    if "<script>" in response.text or "javascript:" in response.text:
                        with self.lock:
                            self.results.append(f"[XSS] Vulnerability found: {vuln_url}")
                        print(Fore.GREEN + f"[XSS] Vulnerability found: {vuln_url}" + Style.RESET_ALL)
                        vulnerable = True
                        break
                except requests.RequestException:
                    continue
            if not vulnerable:
                print(Fore.RED + f"[XSS] Not vulnerable: {fuzz_url}" + Style.RESET_ALL)

        threads = []
        for fuzz_url in self.fuzzed_params:
            t = threading.Thread(target=scan_for_xss, args=(fuzz_url,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

    def scan_rce(self):
        print("[*] Start scanning for RCE vulnerabilities...")
        rce_file = os.path.join(self.payloads_dir, "RCE.txt")
        if not os.path.exists(rce_file):
            print(Fore.RED + "Error: RCE.txt not found!" + Style.RESET_ALL)
            return

        with open(rce_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]

        def scan_for_rce(fuzz_url):
            vulnerable = False
            for payload in payloads:
                vuln_url = fuzz_url.replace("FUZZ", payload)
                try:
                    response = requests.get(vuln_url, timeout=5)
                    if "bash" in response.text or "sh" in response.text:
                        with self.lock:
                            self.results.append(f"[RCE] Vulnerability found: {vuln_url}")
                        print(Fore.GREEN + f"[RCE] Vulnerability found: {vuln_url}" + Style.RESET_ALL)
                        vulnerable = True
                        break
                except requests.RequestException:
                    continue
            if not vulnerable:
                print(Fore.RED + f"[RCE] Not vulnerable: {fuzz_url}" + Style.RESET_ALL)

        threads = []
        for fuzz_url in self.fuzzed_params:
            t = threading.Thread(target=scan_for_rce, args=(fuzz_url,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

    def scan_lfi(self):
        print("[*] Start scanning for LFI vulnerabilities...")
        lfi_file = os.path.join(self.payloads_dir, "LFI.txt")
        if not os.path.exists(lfi_file):
            print(Fore.RED + "Error: LFI.txt not found!" + Style.RESET_ALL)
            return

        with open(lfi_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]

        def scan_for_lfi(fuzz_url):
            vulnerable = False
            for payload in payloads:
                vuln_url = fuzz_url.replace("FUZZ", payload)
                try:
                    response = requests.get(vuln_url, timeout=5)
                    if "etc/passwd" in response.text or "etc/hosts" in response.text:
                        with self.lock:
                            self.results.append(f"[LFI] Vulnerability found: {vuln_url}")
                        print(Fore.GREEN + f"[LFI] Vulnerability found: {vuln_url}" + Style.RESET_ALL)
                        vulnerable = True
                        break
                except requests.RequestException:
                    continue
            if not vulnerable:
                print(Fore.RED + f"[LFI] Not vulnerable: {fuzz_url}" + Style.RESET_ALL)

        threads = []
        for fuzz_url in self.fuzzed_params:
            t = threading.Thread(target=scan_for_lfi, args=(fuzz_url,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

    def scan_rfi(self):
        print("[*] Start scanning for RFI vulnerabilities...")
        rfi_file = os.path.join(self.payloads_dir, "RFI.txt")
        if not os.path.exists(rfi_file):
            print(Fore.RED + "Error: RFI.txt not found!" + Style.RESET_ALL)
            return

        with open(rfi_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]

        def scan_for_rfi(fuzz_url):
            vulnerable = False
            for payload in payloads:
                vuln_url = fuzz_url.replace("FUZZ", payload)
                try:
                    response = requests.get(vuln_url, timeout=5)
                    if "http://" in response.text or "https://" in response.text:
                        with self.lock:
                            self.results.append(f"[RFI] Vulnerability found: {vuln_url}")
                        print(Fore.GREEN + f"[RFI] Vulnerability found: {vuln_url}" + Style.RESET_ALL)
                        vulnerable = True
                        break
                except requests.RequestException:
                    continue
            if not vulnerable:
                print(Fore.RED + f"[RFI] Not vulnerable: {fuzz_url}" + Style.RESET_ALL)

        threads = []
        for fuzz_url in self.fuzzed_params:
            t = threading.Thread(target=scan_for_rfi, args=(fuzz_url,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

    def scan_ssrf(self):
        print("[*] Start scanning for SSRF vulnerabilities...")
        ssrf_file = os.path.join(self.payloads_dir, "SSRF.txt")
        if not os.path.exists(ssrf_file):
            print(Fore.RED + "Error: SSRF.txt not found!" + Style.RESET_ALL)
            return

        with open(ssrf_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]

        def scan_for_ssrf(fuzz_url):
            vulnerable = False
            for payload in payloads:
                vuln_url = fuzz_url.replace("FUZZ", payload)
                try:
                    response = requests.get(vuln_url, timeout=5)
                    if "http://" in response.text or "https://" in response.text:
                        with self.lock:
                            self.results.append(f"[SSRF] Vulnerability found: {vuln_url}")
                        print(Fore.GREEN + f"[SSRF] Vulnerability found: {vuln_url}" + Style.RESET_ALL)
                        vulnerable = True
                        break
                except requests.RequestException:
                    continue
            if not vulnerable:
                print(Fore.RED + f"[SSRF] Not vulnerable: {fuzz_url}" + Style.RESET_ALL)

        threads = []
        for fuzz_url in self.fuzzed_params:
            t = threading.Thread(target=scan_for_ssrf, args=(fuzz_url,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

    def scan_xxe(self):
        print("[*] Start scanning for XXE vulnerabilities...")
        xxe_file = os.path.join(self.payloads_dir, "XXE.txt")
        if not os.path.exists(xxe_file):
            print(Fore.RED + "Error: XXE.txt not found!" + Style.RESET_ALL)
            return

        with open(xxe_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]

        def scan_for_xxe(fuzz_url):
            vulnerable = False
            for payload in payloads:
                vuln_url = fuzz_url.replace("FUZZ", payload)
                try:
                    response = requests.get(vuln_url, timeout=5)
                    if "xml" in response.text or "DTD" in response.text:
                        with self.lock:
                            self.results.append(f"[XXE] Vulnerability found: {vuln_url}")
                        print(Fore.GREEN + f"[XXE] Vulnerability found: {vuln_url}" + Style.RESET_ALL)
                        vulnerable = True
                        break
                except requests.RequestException:
                    continue
            if not vulnerable:
                print(Fore.RED + f"[XXE] Not vulnerable: {fuzz_url}" + Style.RESET_ALL)

        threads = []
        for fuzz_url in self.fuzzed_params:
            t = threading.Thread(target=scan_for_xxe, args=(fuzz_url,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

    def save_results(self):
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        with open(self.output_file, 'w') as f:
            f.write("Scan Results:\n")
            for result in self.results:
                f.write(result + "\n")

    def display_results(self):
        print("\n[*] Scan complete. Vulnerabilities found:")
        if self.results:
            for result in self.results:
                print(Fore.GREEN + result + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "No vulnerabilities found." + Style.RESET_ALL)

    def start_scan(self, update=False):
        if update:
            self.update_code()
        self.fuzz_subdomains()
        self.brute_force_directories()
        self.brute_force_php_files()
        print("[*] Starting parameter fuzzing...")
        self.fuzz_parameters()
        self.scan_vulnerabilities()
        if self.wordlist:
            pass
        self.save_results()
        self.display_results()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The code is a tool for identifying web application vulnerabilities through multithreaded scanning.")
    parser.add_argument("-u", "--host", required=True, help="Target host/domain")
    parser.add_argument("-p", "--payloads-dir", required=True, help="Directory containing payloads")
    parser.add_argument("-o", "--output", required=True, help="Output file for results")
    parser.add_argument("-w", "--wordlist", help="Wordlist of URLs to scan (optional)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--update", action='store_true', help="Update the code from the GitHub repository")
    args = parser.parse_args()

    if args.update:
        scanner = VulnerabilityScanner("", "", "", "", 0)
        scanner.update_code()
    else:
        scanner = VulnerabilityScanner(args.host, args.payloads_dir, args.output, args.wordlist, args.threads)
        scanner.start_scan(update=args.update)
