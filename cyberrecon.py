import argparse
import logging
import sys
import os
import platform
import subprocess
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from pathlib import Path
import json
import re
import requests

BANNER_CYBERRECON = r"""
   _____       _               _____                     
  / ____|     | |             |  __ \                    
 | |     _   _| |__   ___ _ __| |__) |___  ___ ___  _ __  
 | |    | | | | '_ \ / _ \ '__|  _  // _ \/ __/ _ \| '_ \ 
 | |____| |_| | |_) |  __/ |  | | \ \  __/ (_| (_) | | | |
  \_____\__,_|_.__/ \___|_|  |_|  \_\___|\___\___/|_| |_|
                                                          
                    CyberRecon v1.0
           Automated Reconnaissance & OSINT Tool
                  Made by: Belal Mostafa
"""

def print_banner():
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        print(Fore.CYAN + BANNER_CYBERRECON + Style.RESET_ALL)
    except ImportError:
        # Fallback: no color if colorama isn't installed
        print(BANNER_CYBERRECON)

if __name__ == "__main__":
    print_banner()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_subprocess(cmd, timeout=180, check=True, shell=True, capture_output=False):
    try:
        result = subprocess.run(cmd, timeout=timeout, check=check, shell=shell, capture_output=capture_output, text=True)
        return result.stdout if capture_output else True
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {cmd}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}\nError: {e}")
    return None

def check_dependencies():
    required_packages = {
        'dnspython': 'dns',
        'requests': 'requests',
        'python-nmap': 'nmap',
        'pywhois': 'whois'
    }
    missing = []
    for pip_name, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)
    if missing:
        logger.error(f"Missing Python packages: {', '.join(missing)}")
        logger.error("Run: pip install " + " ".join(missing))
        sys.exit(1)

check_dependencies()
import dns.resolver
import nmap
import whois

os.environ["PATH"] = f"{os.path.expanduser('~/.local/bin')}:" + os.environ["PATH"]

class CyberRecon:
    TOOL_LIST = [
        'sublist3r', 'subfinder', 'amass', 'nikto', 'gobuster', 'ffuf',
        'dirsearch', 'theHarvester', 'recon-ng', 'nmap', 'spiderfoot'
    ]
    DIRSCAN_TOOLS = ['ffuf', 'gobuster', 'dirsearch']

    def __init__(self, output_dir="cyberrecon_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.tools_dir = self.output_dir / "tools"
        self.tools_dir.mkdir(exist_ok=True)
        self.wordlist_path = self.output_dir / 'common.txt'
        self.tools_available = {tool: False for tool in self.TOOL_LIST}
        self.nm = nmap.PortScanner()
        self.resolver = dns.resolver.Resolver()
        self.last_subdomains_result = set()  # Store for vuln scan use

    def is_tool_installed(self, tool_name):
        return shutil.which(tool_name) is not None

    def ensure_tool_installed(self, tool):
        # Subdomain tools as before...
        if tool == "sublist3r":
            if not self.is_tool_installed("sublist3r"):
                print("[*] Installing sublist3r via pip...")
                try:
                    subprocess.run(
                        [sys.executable, "-m", "pip", "install", "sublist3r"],
                        check=True
                    )
                except Exception as e:
                    print(f"[!] Could not install sublist3r: {e}")
        elif tool in ("subfinder", "amass"):
            if not self.is_tool_installed(tool):
                if not shutil.which("go"):
                    print(f"[!] Cannot install {tool}: Go is not installed!")
                    return
                print(f"[*] Installing {tool} via Go...")
                gobin = os.path.expanduser("~/.local/bin")
                os.makedirs(gobin, exist_ok=True)
                if tool == "subfinder":
                    go_get = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
                else:
                    go_get = "github.com/owasp-amass/amass/v4/...@master"
                try:
                    subprocess.run(
                        f'GO111MODULE=on GOBIN="{gobin}" go install -v {go_get}',
                        shell=True, check=True
                    )
                except Exception as e:
                    print(f"[!] Could not install {tool}: {e}")
        # OSINT tools
        elif tool == "theHarvester":
            if not self.is_tool_installed("theHarvester"):
                print("[*] Installing theHarvester from GitHub...")
                target = self.tools_dir / "theHarvester"
                if not target.exists():
                    subprocess.run(f"git clone https://github.com/laramies/theHarvester {target}", shell=True, check=True)
                    subprocess.run(f"pip install -r {target}/requirements/base.txt", shell=True, check=True)
                # Symlink theHarvester.py as 'theHarvester' in ~/.local/bin
                local_bin = os.path.expanduser("~/.local/bin")
                os.makedirs(local_bin, exist_ok=True)
                link_path = os.path.join(local_bin, "theHarvester")
                target_path = str(target / "theHarvester.py")
                if os.path.islink(link_path) or os.path.exists(link_path):
                    os.remove(link_path)
                os.symlink(target_path, link_path)
                try:
                    os.chmod(target_path, 0o755)
                except Exception as e:
                    print(f"Warning: Could not chmod {target_path}: {e}")
        elif tool == "spiderfoot":
            if not self.is_tool_installed("sf"):
                print("[*] Installing SpiderFoot from GitHub...")
                target = self.tools_dir / "spiderfoot"
                if not target.exists():
                    subprocess.run(f"git clone https://github.com/smicallef/spiderfoot {target}", shell=True, check=True)
                    subprocess.run(f"pip install -r {target}/requirements.txt", shell=True, check=True)
                # Symlink sf.py as 'sf' in ~/.local/bin
                local_bin = os.path.expanduser("~/.local/bin")
                os.makedirs(local_bin, exist_ok=True)
                link_path = os.path.join(local_bin, "sf")
                target_path = str(target / "sf.py")
                if os.path.islink(link_path) or os.path.exists(link_path):
                    os.remove(link_path)
                os.symlink(target_path, link_path)
                try:
                    os.chmod(target_path, 0o755)
                except Exception as e:
                    print(f"Warning: Could not chmod {target_path}: {e}")
        elif tool == "recon-ng":
            if not self.is_tool_installed("recon-ng"):
                print("[*] Installing recon-ng from GitHub...")
                target = self.tools_dir / "recon-ng"
                if not target.exists():
                    subprocess.run(f"git clone https://github.com/lanmaster53/recon-ng {target}", shell=True, check=True)
                    subprocess.run(f"pip install -r {target}/REQUIREMENTS", shell=True, check=True)
                # Symlink recon-ng as 'recon-ng' in ~/.local/bin
                local_bin = os.path.expanduser("~/.local/bin")
                os.makedirs(local_bin, exist_ok=True)
                link_path = os.path.join(local_bin, "recon-ng")
                target_path = str(target / "recon-ng")
                if os.path.islink(link_path) or os.path.exists(link_path):
                    os.remove(link_path)
                os.symlink(target_path, link_path)
                try:
                    os.chmod(target_path, 0o755)
                except Exception as e:
                    print(f"Warning: Could not chmod {target_path}: {e}")

    def ensure_subdomain_tools(self):
        for tool in ["sublist3r", "subfinder", "amass"]:
            self.ensure_tool_installed(tool)
        os.environ["PATH"] = f"{os.path.expanduser('~/.local/bin')}:" + os.environ["PATH"]

    def ensure_osint_tools(self):
        for tool in ["theHarvester", "spiderfoot", "recon-ng"]:
            self.ensure_tool_installed(tool)
        os.environ["PATH"] = f"{os.path.expanduser('~/.local/bin')}:" + os.environ["PATH"]

    def check_tools(self):
        print("\n[Tool Status Report]\n")
        for tool in self.TOOL_LIST:
            local = self.tools_dir / tool
            marker = self.tools_dir / f".{tool}.installed"
            in_path = shutil.which(tool)
            status = "INSTALLED" if marker.exists() or in_path or local.exists() else "MISSING"
            print(f"{tool:15} : {status}")
        print()

    def osint_scan(self, domain):
        self.ensure_osint_tools()
        results = {'emails': set(), 'subdomains': set(), 'hosts': set(), 'names': set(), 'links': set()}
        lock = threading.Lock()
        tool_used = False


        def run_theharvester():
            nonlocal tool_used
            output_file = self.output_dir / 'theharvester.txt'

            exe = shutil.which("theHarvester") or shutil.which("theharvester")
            if exe:
                cmd = f'"{exe}" -d {domain} -l 500 -b all -f "{output_file}"'
            else:
                repo_script = self.tools_dir / "theHarvester" / "theHarvester.py"
                if repo_script.exists():
                    cmd = f'{sys.executable} "{repo_script}" -d {domain} -l 500 -b all -f "{output_file}"'
                else:
                    logger.warning("theHarvester not installed.")
                    return

            tool_used = True
            run_subprocess(cmd)
            if output_file.exists():
                data = output_file.read_text()
                with lock:
                    results['emails'].update(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', data))
                    results['subdomains'].update(re.findall(r'[\w\.-]+\.' + re.escape(domain), data))
                    results['hosts'].update(re.findall(r'\d+\.\d+\.\d+\.\d+', data))
                    results['names'].update(re.findall(r'[A-Z][a-z]+\s[A-Z][a-z]+', data))

        def run_spiderfoot():
            nonlocal tool_used
            output_file = self.output_dir / 'spiderfoot.json'

            exe = shutil.which("sf") or shutil.which("spiderfoot")
            if exe:
                cmd = f'"{exe}" -s {domain} -m sfp_spider,sfp_dnsresolve,sfp_email,sfp_name -o json > "{output_file}"'
            else:
                repo_script = self.tools_dir / "spiderfoot" / "sf.py"
                if repo_script.exists():
                    cmd = f'{sys.executable} "{repo_script}" -s {domain} -m sfp_spider,sfp_dnsresolve,sfp_email,sfp_name -o json > "{output_file}"'
                else:
                    logger.warning("SpiderFoot not installed.")
                    return

            tool_used = True
            run_subprocess(cmd)
            if output_file.exists():
                try:
                    data = json.loads(output_file.read_text())
                    with lock:
                        for item in data:
                            if item.get('type') == 'EMAILADDR':
                                results['emails'].add(item.get('data'))
                            elif item.get('type') == 'SUBDOMAIN':
                                results['subdomains'].add(item.get('data'))
                            elif item.get('type') == 'IP_ADDRESS':
                                results['hosts'].add(item.get('data'))
                            elif item.get('type') == 'HUMAN_NAME':
                                results['names'].add(item.get('data'))
                except Exception as e:
                    logger.error(f"SpiderFoot JSON parse failed: {e}")

        def run_recon_ng():
            nonlocal tool_used
            output_file = self.output_dir / 'recon-ng.txt'

            exe = shutil.which("recon-ng")
            if exe:
                runner = exe
            else:
                repo_script = self.tools_dir / "recon-ng" / "recon-ng"
                if repo_script.exists():
                    runner = f'{sys.executable} "{repo_script}"'
                else:
                    logger.warning("Recon-ng not installed.")
                    return

            tool_used = True
            recon_ng_script = (
                f"echo -e 'workspaces add {domain}\\n"
                f"modules load recon/domains-hosts/hackertarget\\n"
                f"run\\n"
                f"modules load recon/companies-contacts/linkedin_crawl\\n"
                f"run\\n"
                f"modules load recon/domains-contacts/hunter_io\\n"
                f"run\\n"
                f"show hosts\\n"
                f"show contacts\\n"
                f"exit' | {runner} -w {domain} > \"{output_file}\""
            )
            run_subprocess(recon_ng_script)
            if output_file.exists():
                data = output_file.read_text()
                with lock:
                    results['emails'].update(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', data))
                    results['subdomains'].update(re.findall(r'[\w\.-]+\.' + re.escape(domain), data))
                    results['hosts'].update(re.findall(r'\d+\.\d+\.\d+\.\d+', data))
                    results['names'].update(re.findall(r'[A-Z][a-z]+\s[A-Z][a-z]+', data))

        def run_public_web_scrape():
            base_url = f"https://{domain}"
            seen_urls = set()
            to_visit = [base_url]
            max_pages = 3
            page_count = 0
            while to_visit and page_count < max_pages:
                url = to_visit.pop(0)
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        page_count += 1
                        html = response.text
                        with lock:
                            results['emails'].update(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', html))
                            results['subdomains'].update(re.findall(r'[\w\.-]+\.' + re.escape(domain), html))
                            results['hosts'].update(re.findall(r'\d+\.\d+\.\d+\.\d+', html))
                            for m in re.findall(r'href=[\'"]?([^\'" >]+)', html):
                                full_url = urljoin(url, m)
                                if full_url.startswith(base_url) and full_url not in seen_urls and full_url not in to_visit:
                                    results['links'].add(full_url)
                                    to_visit.append(full_url)
                except Exception:
                    continue

        threads = []
        for f in [run_theharvester, run_spiderfoot, run_recon_ng]:
            t = threading.Thread(target=f)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        if not tool_used:
            print("[!] No OSINT tools (theHarvester, SpiderFoot, recon-ng) installed or working. Only basic scraping will be used.")
        run_public_web_scrape()

        output_file_txt = self.output_dir / f"osint_{domain}.txt"
        output_file_json = self.output_dir / f"osint_{domain}.json"
        with open(output_file_txt, 'w') as f:
            f.write(f"OSINT Results for {domain}\n")
            for key, vals in results.items():
                f.write(f"{key.capitalize()}:\n" + "\n".join(vals) + "\n\n")
        with open(output_file_json, 'w') as f:
            json.dump({k: list(v) for k, v in results.items()}, f, indent=4)
        return results

    def enumerate_dns_records(self, target):
        try:
            return [str(rdata) for rdata in self.resolver.resolve(target, 'A')]
        except Exception as e:
            logger.warning(f"DNS lookup failed: {e}")
            return []

    def whois_lookup(self, target):
        try:
            return whois.whois(target)
        except Exception as e:
            logger.warning(f"WHOIS lookup failed: {e}")
            return {}

    def subdomain_enumeration(self, target):
        self.ensure_subdomain_tools()
        subdomains = set()
        if self.is_tool_installed("sublist3r"):
            outfile = self.output_dir / f"sublist3r_{target}.txt"
            print(f"[*] Running sublist3r for {target}...")
            try:
                subprocess.run(
                    f"sublist3r -d {target} -o {outfile}",
                    shell=True, check=True
                )
                if outfile.exists():
                    with open(outfile) as f:
                        subdomains.update([line.strip() for line in f if line.strip()])
            except Exception as e:
                print(f"[!] sublist3r failed: {e}")
        if self.is_tool_installed("subfinder"):
            outfile = self.output_dir / f"subfinder_{target}.txt"
            print(f"[*] Running subfinder for {target}...")
            try:
                subprocess.run(
                    f"subfinder -d {target} -o {outfile} -silent",
                    shell=True, check=True
                )
                if outfile.exists():
                    with open(outfile) as f:
                        subdomains.update([line.strip() for line in f if line.strip()])
            except Exception as e:
                print(f"[!] subfinder failed: {e}")
        if self.is_tool_installed("amass"):
            outfile = self.output_dir / f"amass_{target}.txt"
            print(f"[*] Running amass for {target}...")
            try:
                subprocess.run(
                    f"amass enum -d {target} -o {outfile}",
                    shell=True, check=True
                )
                if outfile.exists():
                    with open(outfile) as f:
                        subdomains.update([line.strip() for line in f if line.strip()])
            except Exception as e:
                print(f"[!] amass failed: {e}")
        self.last_subdomains_result = subdomains
        return subdomains

    def port_scan(self, target, nmap_args):
        try:
            self.nm.scan(hosts=target, arguments=nmap_args)
            output_file = self.output_dir / f"scan_{target.replace('.', '_')}.txt"
            results = self.nm.csv().splitlines()
            with open(output_file, "w") as f:
                for row in results:
                    f.write(row + "\n")
            print(f"[+] Scan results saved to {output_file}")
            return results
        except Exception as e:
            logger.warning(f"Nmap scan failed: {e}")
            return []

    def dir_scan(self, url):
        self.setup_dirscan_tools()
        results = {}
        wordlist = self.wordlist_path
        if not wordlist.exists():
            print("[*] Downloading wordlist...")
            subprocess.run(f"curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o {wordlist}", shell=True, check=True)

        safeurl = url.replace('://', '_').replace('/', '_')
        threads = []

        ffuf_out = self.output_dir / f"ffuf_{safeurl}.json"
        def run_ffuf():
            print("[*] Running ffuf...")
            try:
                subprocess.run(
                    f'ffuf -u {url}/FUZZ -w {wordlist} -o {ffuf_out} -of json -t 30',
                    shell=True, check=True)
                results['ffuf'] = ffuf_out.read_text()
            except Exception as e:
                results['ffuf'] = f"ffuf failed: {e}"

        gobuster_out = self.output_dir / f"gobuster_{safeurl}.txt"
        def run_gobuster():
            print("[*] Running gobuster...")
            try:
                subprocess.run(
                    f'gobuster dir -u {url} -w {wordlist} -o {gobuster_out} -q -t 5 -to 30s',
                    shell=True, check=True)
                results['gobuster'] = gobuster_out.read_text()
            except Exception as e:
                results['gobuster'] = f"gobuster failed: {e}"

        dirsearch_path = self.tools_dir / "dirsearch"
        dirsearch_out = self.output_dir / f"dirsearch_{safeurl}.txt"
        def run_dirsearch():
            print("[*] Running dirsearch...")
            try:
                subprocess.run(
                    f'python3 {dirsearch_path}/dirsearch.py -u {url} -w {wordlist} -o {dirsearch_out}',
                    shell=True, check=True)
                results['dirsearch'] = dirsearch_out.read_text()
            except Exception as e:
                results['dirsearch'] = f"dirsearch failed: {e}"

        t1 = threading.Thread(target=run_ffuf)
        t2 = threading.Thread(target=run_gobuster)
        t3 = threading.Thread(target=run_dirsearch)
        for t in [t1, t2, t3]:
            t.start()
        for t in [t1, t2, t3]:
            t.join()

        combined_out = self.output_dir / f"dirscan_{safeurl}_combined.txt"
        with open(combined_out, "w") as f:
            for tool, res in results.items():
                f.write(f"==== {tool.upper()} ====\n{res}\n\n")
        print(f"\n[+] All scan results saved to {combined_out}")
        return results

    def resolve_domain(self, subdomain):
        try:
            self.resolver.resolve(subdomain, "A")
            return True
        except Exception:
            return False

    def vuln_scan(self, subdomain):
        results = []
        if not self.resolve_domain(subdomain):
            return [f"{subdomain} did not resolve"]
        nikto_out = self.output_dir / f"nikto_{subdomain}.txt"
        try:
            print(f"[*] Running nikto for {subdomain} ...")
            subprocess.run(
                f"nikto -h {subdomain} -output {nikto_out}",
                shell=True,
                check=True
            )
            if nikto_out.exists():
                results = nikto_out.read_text().splitlines()
        except Exception as e:
            results = [f"Nikto failed: {e}"]
        return results

    def setup_dirscan_tools(self):
        if not self.is_tool_installed("ffuf"):
            self.install_ffuf()
        if not self.is_tool_installed("gobuster"):
            self.install_gobuster()
        dirsearch_path = self.tools_dir / "dirsearch"
        if not dirsearch_path.exists():
            self.install_dirsearch()

    def install_ffuf(self):
        if not self.is_tool_installed("ffuf"):
            print("[*] Installing ffuf...")
            try:
                subprocess.run("go install github.com/ffuf/ffuf/v2@latest", shell=True, check=True)
                gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
                ffuf_path = os.path.join(gopath, "bin", "ffuf")
                if os.path.exists(ffuf_path):
                    user_bin = os.path.expanduser("~/.local/bin")
                    os.makedirs(user_bin, exist_ok=True)
                    shutil.copy(ffuf_path, user_bin)
            except Exception as e:
                print(f"[!] Could not install ffuf: {e}")

    def install_gobuster(self):
        if not self.is_tool_installed("gobuster"):
            print("[*] Installing gobuster...")
            try:
                subprocess.run("go install github.com/OJ/gobuster/v3@latest", shell=True, check=True)
                gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
                gobuster_path = os.path.join(gopath, "bin", "gobuster")
                if os.path.exists(gobuster_path):
                    user_bin = os.path.expanduser("~/.local/bin")
                    os.makedirs(user_bin, exist_ok=True)
                    shutil.copy(gobuster_path, user_bin)
            except Exception as e:
                print(f"[!] Could not install gobuster: {e}")

    def install_dirsearch(self):
        dirsearch_path = self.tools_dir / "dirsearch"
        if not dirsearch_path.exists():
            print("[*] Cloning dirsearch...")
            try:
                subprocess.run(
                    f"git clone https://github.com/maurosoria/dirsearch {dirsearch_path}",
                    shell=True, check=True)
                subprocess.run(
                    f"pip install -r {dirsearch_path}/requirements.txt",
                    shell=True, check=True)
            except Exception as e:
                print(f"[!] Could not install dirsearch: {e}")
        else:
            print("[*] dirsearch already cloned.")

    def setup_tools(self):
        pass  # For brevity, as before

def main():
    parser = argparse.ArgumentParser(
        description="CyberRecon: Automated Cybersecurity CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--install-tools', action='store_true', help='Install missing tools')
    parser.add_argument('--output-dir', default="cyberrecon_output", help='Output directory')
    parser.add_argument('--output-format', choices=['text', 'json'], default='text', help='Output format')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    parser_check = subparsers.add_parser('check', help='Check installed status of all external tools')
    parser_info = subparsers.add_parser('info', help='Domain/IP info (DNS, WHOIS, subdomains)')
    parser_info.add_argument('target')
    parser_scan = subparsers.add_parser('scan', help='Port scan')
    parser_scan.add_argument('target')
    parser_scan.add_argument('--args', default='-sV -T4', help='Nmap arguments')
    parser_dir = subparsers.add_parser('dirscan', help='Directory scan')
    parser_dir.add_argument('url')
    parser_vuln = subparsers.add_parser('vuln', help='Vuln scan on subdomains')
    parser_vuln.add_argument('domain')
    parser_osint = subparsers.add_parser('osint', help='OSINT scan')
    parser_osint.add_argument('domain')

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    recon = CyberRecon(output_dir=args.output_dir)

    if args.install_tools:
        recon.setup_tools()

    if args.command == 'check':
        recon.check_tools()
    elif args.command == 'info':
        logger.info(f"Gathering info for {args.target}")
        dns_records = recon.enumerate_dns_records(args.target)
        whois_data = recon.whois_lookup(args.target)
        subdomains = recon.subdomain_enumeration(args.target)
        recon.last_subdomains_result = subdomains
        if args.output_format == "json":
            print(json.dumps({
                "dns_records": dns_records,
                "whois_data": whois_data,
                "subdomains": list(subdomains)
            }, indent=2))
        else:
            print(f"DNS Records: {dns_records}")
            print(f"WHOIS Data: {whois_data}")
            print(f"Subdomains: {subdomains}")
    elif args.command == 'scan':
        logger.info(f"Scanning ports for {args.target}")
        results = recon.port_scan(args.target, args.args)
        output_path = Path(args.output_dir) / f"scan_{args.target.replace('.', '_')}.txt"
        if args.output_format == "json":
            import csv
            import io
            reader = csv.DictReader(io.StringIO('\n'.join(results)))
            scan_results = list(reader)
            print(json.dumps({"scan_results": scan_results}, indent=2))
            with open(output_path.with_suffix(".json"), "w") as f:
                json.dump({"scan_results": scan_results}, f, indent=2)
        else:
            for i, row in enumerate(results):
                if i == 0:
                    print("-" * 80)
                    print(row.replace(";", " | "))
                    print("-" * 80)
                else:
                    print(row.replace(";", " | "))
    elif args.command == 'dirscan':
        logger.info(f"Directory scan for {args.url}")
        results = recon.dir_scan(args.url)
        output_path = Path(args.output_dir) / f"dirscan_{args.url.replace('://', '_').replace('/', '_')}_combined.txt"
        if args.output_format == "json":
            print(json.dumps(results, indent=2))
        else:
            for tool, res in results.items():
                print(f"\n==== {tool.upper()} ====\n{res}\n")
        print(f"[+] All scan results saved to {output_path}")
    elif args.command == 'vuln':
        logger.info(f"Vuln scan for subdomains of {args.domain}")
        if recon.last_subdomains_result:
            subdomains = recon.last_subdomains_result
        else:
            subdomains = recon.subdomain_enumeration(args.domain)
        all_results = []
        for subdomain in subdomains:
            if recon.resolve_domain(subdomain):
                logger.info(f"Nikto scan for {subdomain}...")
                results = recon.vuln_scan(subdomain)
                all_results.append({subdomain: results})
        if args.output_format == "json":
            print(json.dumps({"vuln_scan_results": all_results}, indent=2))
        else:
            for item in all_results:
                print(item)
    elif args.command == 'osint':
        logger.info(f"OSINT scan for {args.domain}")
        results = recon.osint_scan(args.domain)
        if args.output_format == "json":
            print(json.dumps({k: list(v) for k, v in results.items()}, indent=2))
        else:
            print("OSINT Results:")
            for k, v in results.items():
                print(f"{k.capitalize()}: {', '.join(v) if v else 'None'}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()