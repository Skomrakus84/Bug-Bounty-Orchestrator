import asyncio
import json
import tempfile
import os

class ScannerEngine:
    def __init__(self, target_url: str):
        self.target_url = target_url
        # Load filtering configuration from environment variables
        self.filter_config = {
            "ignore_theoretical": os.getenv("FILTER_IGNORE_THEORETICAL", "true").lower() == "true",
            "ignore_self_xss": os.getenv("FILTER_IGNORE_SELF_XSS", "true").lower() == "true",
            "ignore_version_disclosure": os.getenv("FILTER_IGNORE_VERSION_DISCLOSURE", "true").lower() == "true",
            "ignore_cookie_flags": os.getenv("FILTER_IGNORE_COOKIE_FLAGS", "true").lower() == "true",
            "ignore_clickjacking": os.getenv("FILTER_IGNORE_CLICKJACKING", "true").lower() == "true",
            "ignore_csrf": os.getenv("FILTER_IGNORE_CSRF", "true").lower() == "true",
            "ignore_open_redirect": os.getenv("FILTER_IGNORE_OPEN_REDIRECT", "true").lower() == "true",
            "ignore_email_security": os.getenv("FILTER_IGNORE_EMAIL_SECURITY", "true").lower() == "true",
            "ignore_rate_limiting": os.getenv("FILTER_IGNORE_RATE_LIMITING", "true").lower() == "true",
            "ignore_physical_access": os.getenv("FILTER_IGNORE_PHYSICAL_ACCESS", "true").lower() == "true",
            "ignore_unverified_scans": os.getenv("FILTER_IGNORE_UNVERIFIED_SCANS", "true").lower() == "true",
            "ignore_eol_systems": os.getenv("FILTER_IGNORE_EOL_SYSTEMS", "true").lower() == "true",
            "ignore_common_fp": os.getenv("FILTER_IGNORE_COMMON_FP", "true").lower() == "true"
        }
    async def run_sublist3r(self) -> list:
        import sublist3r
        subdomains = sublist3r.main(self.target_url, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        return [{"host": sub} for sub in subdomains]

    async def run_crtsh(self) -> list:
        import requests
        url = f"https://crt.sh/?q=%25.{self.target_url}&output=json"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    if sub.endswith(self.target_url):
                        subdomains.add(sub.strip())
            return [{"host": sub} for sub in subdomains]
        except Exception as e:
            print(f"crt.sh error: {e}")
            return []

    async def run_whois(self) -> dict:
        import whois
        try:
            w = whois.whois(self.target_url)
            return w.__dict__
        except Exception as e:
            print(f"whois error: {e}")
            return {}

    async def run_dig(self) -> dict:
        import dns.resolver
        result = {}
        try:
            for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
                answers = dns.resolver.resolve(self.target_url, rtype, raise_on_no_answer=False)
                result[rtype] = [str(a) for a in answers]
            return result
        except Exception as e:
            print(f"dig error: {e}")
            return result

    async def run_nslookup(self) -> dict:
        import dns.resolver
        result = {}
        try:
            answers = dns.resolver.resolve(self.target_url, "A", raise_on_no_answer=False)
            result["A"] = [str(a) for a in answers]
            return result
        except Exception as e:
            print(f"nslookup error: {e}")
            return result
    def __init__(self, target_url: str):
        self.target_url = target_url

    async def run_command(self, command: str, input_data: str = None) -> str:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate(input=input_data.encode() if input_data else None)
        if proc.returncode != 0:
            print(f"Command failed: {stderr.decode()}")
            return ""  # Return empty instead of raising
        return stdout.decode()

    async def run_subfinder(self) -> list:
        cmd = f"subfinder -d {self.target_url} -silent"
        output = await self.run_command(cmd)
        # Parse output as lines
        subdomains = [line.strip() for line in output.splitlines() if line.strip()]
        return [{"host": subdomain} for subdomain in subdomains]

    # async def run_amass(self) -> list:
    #     cmd = f"amass enum -d {self.target_url} --passive"
    #     output = await self.run_command(cmd)
    #     subdomains = [line.strip() for line in output.splitlines() if line.strip()]
    #     return [{"host": subdomain} for subdomain in subdomains]

    async def run_httpx(self, subdomains: list) -> list:
        input_data = "\n".join([s.get("host", "") for s in subdomains])
        cmd = "httpx -s"
        output = await self.run_command(cmd, input_data=input_data)
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        return [{"url": url} for url in urls]

    async def run_nmap(self, live_urls: list) -> list:
        results = []
        for url in live_urls:
            host = url.get("url", "").replace("http://", "").replace("https://", "").split("/")[0]
            cmd = f"nmap -Pn {host} -oX -"
            output = await self.run_command(cmd)
            results.append(output)
        return results

    async def run_nuclei(self, live_urls: list) -> list:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            for url in live_urls:
                f.write(url.get("url", "") + "\n")
            temp_path = f.name
        cmd = f"nuclei -l {temp_path} -silent"
        output = await self.run_command(cmd)
        # Parse nuclei output (simplified)
        results = []
        for line in output.splitlines():
            if line.strip():
                # Assume format: [severity] url - template
                parts = line.split(" - ")
                if len(parts) >= 2:
                    results.append({
                        "templateID": parts[1].strip(),
                        "severity": "info",  # default
                        "matched": parts[0].strip()
                    })
        return results

    # async def run_naabu(self) -> list:
    #     cmd = f"naabu -host {self.target_url} -silent"
    #     output = await self.run_command(cmd)
    #     ports = [line.strip() for line in output.splitlines() if line.strip()]
    #     return [{"port": port} for port in ports]

    async def run_ffuf(self, url: str, wordlist: str = "/opt/dirsearch/db/dicc.txt") -> list:
        cmd = f"ffuf -u {url}/FUZZ -w {wordlist} -of json -o /tmp/ffuf_out.json -s"
        await self.run_command(cmd)
        try:
            with open("/tmp/ffuf_out.json", "r") as f:
                results = json.load(f)
            return results.get("results", [])
        except Exception as e:
            print(f"FFUF error: {e}")
            return []

    async def run_sqlmap(self, url: str) -> list:
        cmd = f"python3 /opt/sqlmap/sqlmap.py -u {url} --batch --output-dir=/tmp/sqlmap_out"
        await self.run_command(cmd)
        # Parsing results can be added here
        return []

    async def run_dirsearch(self, url: str, wordlist: str = "/opt/dirsearch/db/dicc.txt") -> list:
        cmd = f"python3 /opt/dirsearch/dirsearch.py -u {url} -w {wordlist} --format=json --output=/tmp/dirsearch_out.json"
        await self.run_command(cmd)
        try:
            with open("/tmp/dirsearch_out.json", "r") as f:
                results = json.load(f)
            return results.get("results", [])
        except Exception as e:
            print(f"Dirsearch error: {e}")
            return []

    async def run_feroxbuster(self, url: str, wordlist: str = "/opt/dirsearch/db/dicc.txt") -> list:
        cmd = f"feroxbuster -u {url} -w {wordlist} --silent --json"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if line.strip():
                try:
                    result = json.loads(line)
                    results.append(result)
                except json.JSONDecodeError:
                    pass
        return results

    async def run_gobuster(self, url: str, wordlist: str = "/opt/dirsearch/db/dicc.txt") -> list:
        cmd = f"gobuster dir -u {url} -w {wordlist} -q -o /tmp/gobuster_out.txt"
        await self.run_command(cmd)
        results = []
        try:
            with open("/tmp/gobuster_out.txt", "r") as f:
                for line in f:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            results.append({"url": parts[0], "status": parts[1]})
        except FileNotFoundError:
            pass
        return results

    async def run_mitmproxy(self, url: str) -> list:
        # Basic mitmproxy integration - record traffic
        cmd = f"mitmdump --mode transparent --listen-host 0.0.0.0 --listen-port 8080 -s /tmp/mitmproxy_script.py"
        # For simplicity, just run for a short time to capture initial traffic
        # In practice, this would require user interaction or longer run
        output = await self.run_command(cmd)
        return [{"traffic": output}]  # Simplified

    async def run_schemathesis(self, openapi_url: str) -> list:
        cmd = f"schemathesis run {openapi_url} --checks all --hypothesis-max-examples=10"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "FAIL" in line or "ERROR" in line:
                results.append({"issue": line})
        return results

    async def run_restler(self, api_url: str) -> list:
        cmd = f"restler fuzz --grammar_file /tmp/grammar.py --host {api_url}"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "bug" in line.lower() or "error" in line.lower():
                results.append({"issue": line})
        return results

    async def run_playwright(self, url: str) -> list:
        from playwright.async_api import async_playwright
        results = []
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            try:
                await page.goto(url, timeout=10000)
                title = await page.title()
                results.append({"title": title, "url": url})
                # Basic screenshot
                await page.screenshot(path="/tmp/playwright_screenshot.png")
                results.append({"screenshot": "/tmp/playwright_screenshot.png"})
            except Exception as e:
                results.append({"error": str(e)})
            await browser.close()
        return results

    async def run_selenium(self, url: str) -> list:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        options = Options()
        options.add_argument("--headless")
        driver = webdriver.Chrome(options=options)
        results = []
        try:
            driver.get(url)
            title = driver.title
            results.append({"title": title, "url": url})
            # Basic screenshot
            driver.save_screenshot("/tmp/selenium_screenshot.png")
            results.append({"screenshot": "/tmp/selenium_screenshot.png"})
        except Exception as e:
            results.append({"error": str(e)})
        driver.quit()
        return results

    async def run_appium(self, apk_path: str = None) -> list:
        from appium import webdriver
        # Simplified mobile automation - assumes Android emulator running
        desired_caps = {
            "platformName": "Android",
            "deviceName": "emulator-5554",
            "app": apk_path or "/tmp/sample.apk"
        }
        results = []
        try:
            driver = webdriver.Remote("http://localhost:4723/wd/hub", desired_caps)
            # Basic actions
            results.append({"app_launched": True})
            driver.quit()
        except Exception as e:
            results.append({"error": str(e)})
        return results

    async def run_adb(self) -> list:
        cmd = "adb devices"
        output = await self.run_command(cmd)
        devices = [line.split()[0] for line in output.splitlines() if line.strip() and not line.startswith("List")]
        return [{"devices": devices}]

    async def run_apktool(self, apk_path: str = "/tmp/sample.apk") -> list:
        cmd = f"apktool d {apk_path} -o /tmp/apktool_out"
        output = await self.run_command(cmd)
        return [{"decompiled": "/tmp/apktool_out"}]

    async def run_jadx(self, apk_path: str = "/tmp/sample.apk") -> list:
        cmd = f"jadx -d /tmp/jadx_out {apk_path}"
        output = await self.run_command(cmd)
        return [{"decompiled": "/tmp/jadx_out"}]

    async def run_mobsf(self, apk_path: str = "/tmp/sample.apk") -> list:
        cmd = f"mobsf scan {apk_path}"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "vulnerability" in line.lower() or "issue" in line.lower():
                results.append({"issue": line})
        return results

    async def run_frida(self, target_app: str = "com.example.app") -> list:
        cmd = f"frida-ps -U | grep {target_app}"
        output = await self.run_command(cmd)
        return [{"processes": output.splitlines()}]

    async def run_objection(self, target_app: str = "com.example.app") -> list:
        cmd = f"objection -g {target_app} explore --startup-command 'android hooking list activities'"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "activity" in line.lower():
                results.append({"activity": line})
        return results

    async def run_tshark(self, interface: str = "eth0", duration: int = 10) -> list:
        cmd = f"tshark -i {interface} -a duration:{duration} -w /tmp/capture.pcap"
        output = await self.run_command(cmd)
        return [{"capture": "/tmp/capture.pcap"}]

    async def run_tcpreplay(self, pcap_file: str = "/tmp/capture.pcap") -> list:
        cmd = f"tcpreplay --intf1=lo {pcap_file}"
        output = await self.run_command(cmd)
        return [{"replayed": output}]

    async def run_wireshark_analysis(self, pcap_file: str = "/tmp/capture.pcap") -> list:
        cmd = f"tshark -r {pcap_file} -T json"
        output = await self.run_command(cmd)
        import json
        try:
            packets = json.loads(output)
            return packets
        except:
            return [{"error": "Failed to parse packets"}]

    async def run_boofuzz(self, target: str) -> list:
        from boofuzz import Session, Target, SocketConnection
        results = []
        try:
            session = Session(target=Target(connection=SocketConnection(target, 80)))
            session.connect()
            session.fuzz()
            results.append({"fuzzed": target})
        except Exception as e:
            results.append({"error": str(e)})
        return results

    async def run_afl(self, binary: str = "/tmp/sample_binary") -> list:
        cmd = f"afl-fuzz -i /tmp/input -o /tmp/output -- {binary}"
        output = await self.run_command(cmd)
        return [{"fuzz_output": output}]

    async def run_wfuzz(self, url: str, wordlist: str = "/opt/dirsearch/db/dicc.txt") -> list:
        cmd = f"wfuzz -c -z file,{wordlist} {url}/FUZZ"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "200" in line or "403" in line:
                results.append({"url": line.split()[4] if len(line.split()) > 4 else line})
        return results

    async def run_radamsa(self, input_file: str = "/tmp/input.txt") -> list:
        cmd = f"radamsa {input_file}"
        output = await self.run_command(cmd)
        return [{"mutated": output}]

    async def run_peach(self, config: str = "/tmp/peach_config.xml") -> list:
        cmd = f"peach -c {config}"
        output = await self.run_command(cmd)
        return [{"fuzz_output": output}]

    async def run_zzuf(self, binary: str = "/tmp/sample_binary") -> list:
        cmd = f"zzuf -s 0:100 -r 0.01 {binary}"
        output = await self.run_command(cmd)
        return [{"fuzz_output": output}]

    async def run_semgrep(self, path: str = "/tmp/source_code") -> list:
        cmd = f"semgrep --config auto {path}"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "Finding:" in line or "error" in line.lower():
                results.append({"issue": line})
        return results

    async def run_bandit(self, path: str = "/tmp/source_code") -> list:
        cmd = f"bandit -r {path}"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "Issue:" in line or "SEVERITY:" in line:
                results.append({"issue": line})
        return results

    async def run_ghidra(self, binary: str = "/tmp/sample_binary") -> list:
        cmd = f"ghidra-headless /tmp/ghidra_project {binary} -script /tmp/analyze.py"
        output = await self.run_command(cmd)
        return [{"analysis": output}]

    async def run_radare2(self, binary: str = "/tmp/sample_binary") -> list:
        cmd = f"r2 -c 'aaa; afl; q' {binary}"
        output = await self.run_command(cmd)
        return [{"functions": output}]

    async def run_cutter(self, binary: str = "/tmp/sample_binary") -> list:
        cmd = f"cutter -A {binary} --headless"
        output = await self.run_command(cmd)
        return [{"analysis": output}]

    async def run_strings(self, binary: str = "/tmp/sample_binary") -> list:
        cmd = f"strings {binary}"
        output = await self.run_command(cmd)
        return [{"strings": output.splitlines()}]

    async def run_objdump(self, binary: str = "/tmp/sample_binary") -> list:
        cmd = f"objdump -d {binary}"
        output = await self.run_command(cmd)
        return [{"disassembly": output}]

    async def run_readelf(self, binary: str = "/tmp/sample_binary") -> list:
        cmd = f"readelf -a {binary}"
        output = await self.run_command(cmd)
        return [{"elf_info": output}]

    async def run_pandoc(self, markdown_content: str) -> str:
        from integrations import generate_pdf_report
        pdf_path = generate_pdf_report(markdown_content)
        return pdf_path or "PDF generation failed"

    async def run_bugcrowd_api(self, report_content: str, program_id: str) -> dict:
        from integrations import submit_to_bugcrowd
        return submit_to_bugcrowd(report_content, program_id)

    async def run_jira_api(self, report_content: str, project_key: str) -> dict:
        from integrations import submit_to_jira
        return submit_to_jira(report_content, project_key)

    async def run_github_api(self, report_content: str, repo: str) -> dict:
        from integrations import submit_to_github
        return submit_to_github(report_content, repo)

    async def run_jaeles(self, target: str) -> list:
        cmd = f"jaeles scan -u {target}"
        output = await self.run_command(cmd)
        return [{"jaeles_findings": output.splitlines()}]

    async def run_katana(self, target: str) -> list:
        cmd = f"katana -u {target} -jc"
        output = await self.run_command(cmd)
        return [{"katana_urls": output.splitlines()}]

    async def run_uncover(self, target: str) -> list:
        cmd = f"uncover -q {target}"
        output = await self.run_command(cmd)
        return [{"uncover_results": output.splitlines()}]

    async def run_dnsx(self, target: str) -> list:
        cmd = f"dnsx -d {target} -a -aaaa -cname -mx -ns"
        output = await self.run_command(cmd)
        return [{"dnsx_records": output.splitlines()}]

    async def run_alterx(self, target: str) -> list:
        cmd = f"alterx -l {target} -en"
        output = await self.run_command(cmd)
        return [{"alterx_permutations": output.splitlines()}]

    async def run_interactsh(self, domain: str = "interactsh.com") -> list:
        cmd = f"interactsh-client -v -d {domain}"
        output = await self.run_command(cmd)
        return [{"interactsh_logs": output.splitlines()}]

    async def run_nuclei(self, urls: list) -> list:
        """Run Nuclei vulnerability scanner on multiple URLs"""
        all_results = []
        for url_obj in urls[:10]:  # Limit to first 10 URLs to avoid overload
            url = url_obj.get("url", url_obj.get("host", ""))
            if not url.startswith("http"):
                url = f"https://{url}"
            cmd = f"nuclei -u {url} -json -silent"
            output = await self.run_command(cmd)
            results = []
            for line in output.splitlines():
                if line.strip():
                    try:
                        result = json.loads(line)
                        results.append(result)
                    except json.JSONDecodeError:
                        pass
            all_results.extend(results)
        return all_results

    async def run_nikto(self, url: str) -> list:
        """Run Nikto web server scanner"""
        cmd = f"nikto -h {url} -Format json -output /tmp/nikto_out.json"
        await self.run_command(cmd)
        try:
            with open("/tmp/nikto_out.json", "r") as f:
                results = json.load(f)
            return results
        except Exception as e:
            print(f"Nikto error: {e}")
            return []

    async def run_wapiti(self, url: str) -> list:
        """Run Wapiti web application vulnerability scanner"""
        cmd = f"wapiti -u {url} --format json --output /tmp/wapiti_out.json"
        await self.run_command(cmd)
        try:
            with open("/tmp/wapiti_out.json", "r") as f:
                results = json.load(f)
            return results.get("vulnerabilities", [])
        except Exception as e:
            print(f"Wapiti error: {e}")
            return []

    async def run_xsstrike(self, url: str) -> list:
        """Run XSStrike for XSS detection"""
        cmd = f"python3 /opt/XSStrike/xsstrike.py -u {url} --json --output /tmp/xsstrike_out.json"
        await self.run_command(cmd)
        try:
            with open("/tmp/xsstrike_out.json", "r") as f:
                results = json.load(f)
            return results
        except Exception as e:
            print(f"XSStrike error: {e}")
            return []

    async def run_cmseek(self, url: str) -> list:
        """Run CMSeek for CMS detection and exploitation"""
        cmd = f"python3 /opt/CMSeeK/cmseek.py -u {url} --batch"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "[+]" in line or "[!]" in line:
                results.append({"cmseek_finding": line})
        return results

    async def run_skipfish(self, url: str) -> list:
        """Run wfuzz as alternative to skipfish - web application fuzzer"""
        cmd = f"wfuzz -c -z file,/opt/dirsearch/db/dicc.txt --hc 404 {url}/FUZZ"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "200" in line or "403" in line or "500" in line:
                parts = line.split()
                if len(parts) > 3:
                    results.append({"url": parts[3], "status": parts[1]})
        return results

    async def run_arachni(self, url: str) -> list:
        """Run whatweb as alternative to arachni - web technology fingerprinting"""
        cmd = f"whatweb {url}"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "[" in line and "]" in line:
                results.append({"technology": line.strip()})
        return results

    async def run_owasp_zap(self, url: str) -> list:
        """Run basic security checks using available tools"""
        results = []
        # Use nikto for basic checks
        nikto_cmd = f"perl /opt/nikto/program/nikto.pl -h {url} -Tuning 1234567890ab"
        output = await self.run_command(nikto_cmd)
        for line in output.splitlines():
            if "OSVDB" in line or "vulnerable" in line.lower():
                results.append({"zap_finding": line})
        return results

    async def run_lynis(self) -> list:
        """Run Lynis security auditing tool"""
        cmd = "lynis audit system --quiet --no-colors --logfile /tmp/lynis.log"
        output = await self.run_command(cmd)
        results = []
        try:
            with open("/tmp/lynis.log", "r") as f:
                for line in f:
                    if "[WARNING]" in line or "[CRITICAL]" in line:
                        results.append({"lynis_finding": line.strip()})
        except Exception as e:
            print(f"Lynis error: {e}")
        return results

    async def run_openscap(self) -> list:
        """Run OpenSCAP security compliance scanning"""
        cmd = "oscap oval eval --results /tmp/openscap_results.xml /usr/share/openscap/scap-yast2/oval/5.10/oval.xml"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "fail" in line.lower() or "warning" in line.lower():
                results.append({"openscap_finding": line})
        return results

    async def run_clamav(self, path: str = "/tmp") -> list:
        """Run ClamAV antivirus scanning"""
        cmd = f"clamscan -r --log=/tmp/clamav.log {path}"
        output = await self.run_command(cmd)
        results = []
        try:
            with open("/tmp/clamav.log", "r") as f:
                for line in f:
                    if "FOUND" in line:
                        results.append({"clamav_finding": line.strip()})
        except Exception as e:
            print(f"ClamAV error: {e}")
        return results

    async def run_rkhunter(self) -> list:
        """Run RKHunter rootkit detection"""
        cmd = "rkhunter --check --sk --logfile /tmp/rkhunter.log"
        output = await self.run_command(cmd)
        results = []
        try:
            with open("/tmp/rkhunter.log", "r") as f:
                for line in f:
                    if "Warning" in line or "Rootkit" in line:
                        results.append({"rkhunter_finding": line.strip()})
        except Exception as e:
            print(f"RKHunter error: {e}")
        return results

    async def run_chkrootkit(self) -> list:
        """Run chkrootkit rootkit detection"""
        cmd = "chkrootkit | grep -v 'not found' | grep -v 'not infected'"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "INFECTED" in line or "Warning" in line:
                results.append({"chkrootkit_finding": line})
        return results

    async def run_aide(self) -> list:
        """Run AIDE file integrity check"""
        cmd = "aide --check --logfile /tmp/aide.log"
        output = await self.run_command(cmd)
        results = []
        try:
            with open("/tmp/aide.log", "r") as f:
                for line in f:
                    if "changed" in line.lower() or "added" in line.lower():
                        results.append({"aide_finding": line.strip()})
        except Exception as e:
            print(f"AIDE error: {e}")
            # Initialize AIDE database if not exists
            await self.run_command("aide --init")
        return results

    async def run_suricata(self, interface: str = "eth0") -> list:
        """Run Suricata IDS"""
        cmd = f"suricata -c /etc/suricata/suricata.yaml -i {interface} --runmode autofp -l /tmp/suricata_logs"
        # Run for short time
        output = await self.run_command(f"timeout 30 {cmd}")
        results = []
        try:
            import glob
            for log_file in glob.glob("/tmp/suricata_logs/fast.log"):
                with open(log_file, "r") as f:
                    for line in f:
                        results.append({"suricata_alert": line.strip()})
        except Exception as e:
            print(f"Suricata error: {e}")
        return results

    async def run_auditd_analysis(self) -> list:
        """Analyze auditd logs for security events"""
        cmd = "ausearch -m all --start today | head -50"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "failed" in line.lower() or "denied" in line.lower():
                results.append({"auditd_event": line})
        return results

    async def run_fail2ban_status(self) -> list:
        """Check fail2ban status"""
        cmd = "fail2ban-client status"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "jail" in line.lower():
                results.append({"fail2ban_jail": line.strip()})
        return results

    async def run_lynis(self) -> list:
        """Run Lynis security audit on the system"""
        cmd = "lynis audit system --quick"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "[WARNING]" in line or "[SUGGESTION]" in line:
                results.append({"lynis_finding": line})
        return results

    async def run_brakeman(self, path: str = "/tmp/rails_app") -> list:
        """Run Brakeman security scanner for Ruby on Rails"""
        cmd = f"brakeman {path}"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "Confidence:" in line or "Warning:" in line:
                results.append({"brakeman_finding": line})
        return results

    async def run_pmd(self, path: str = "/tmp/source_code", language: str = "java") -> list:
        """Run PMD static analysis"""
        cmd = f"pmd check -d {path} -R rulesets/{language}/quickstart.xml -f text"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "PMD" in line or "Violation" in line:
                results.append({"pmd_finding": line})
        return results

    async def run_clamav(self, path: str = "/tmp/files") -> list:
        """Run ClamAV antivirus scan"""
        cmd = f"clamscan -r {path}"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "FOUND" in line:
                results.append({"clamav_finding": line})
        return results

    async def run_yara(self, file_path: str = "/tmp/suspicious_file", rules_path: str = "/tmp/yara_rules.yar") -> list:
        """Run YARA malware detection"""
        try:
            import yara
            rules = yara.compile(filepath=rules_path)
            matches = rules.match(file_path)
            return [{"yara_matches": [str(match) for match in matches]}]
        except Exception as e:
            return [{"yara_error": str(e)}]

    async def run_openscap(self, profile: str = "xccdf_org.ssgproject.content_profile_standard") -> list:
        """Run OpenSCAP security compliance check"""
        cmd = f"oscap xccdf eval --profile {profile} --results /tmp/openscap_results.xml /usr/share/xml/scap/ssg/content/ssg-rhel8-xccdf.xml"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "fail" in line.lower() or "pass" in line.lower():
                results.append({"openscap_result": line})
        return results

    async def run_safety(self, path: str = "/tmp/python_project") -> list:
        """Run Safety Python dependency vulnerability scanner"""
        cmd = f"safety check --file {path}/requirements.txt"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "vulnerability" in line.lower() or "unsafe" in line.lower():
                results.append({"safety_finding": line})
        return results

    async def run_trivy(self, target: str) -> list:
        """Run Trivy vulnerability scanner"""
        cmd = f"trivy {target}"
        output = await self.run_command(cmd)
        results = []
        for line in output.splitlines():
            if "HIGH" in line or "CRITICAL" in line:
                results.append({"trivy_finding": line})
        return results

    async def run_qualys_like_scan(self, target: str) -> list:
        """Run comprehensive security assessment (Qualys-like)"""
        results = []
        # Combine multiple tools for comprehensive assessment
        tools_results = await asyncio.gather(
            self.run_nikto(target),
            self.run_wapiti(target),
            self.run_clamav("/tmp"),
            self.run_trivy(target),
            return_exceptions=True
        )

        for tool_result in tools_results:
            if isinstance(tool_result, list):
                results.extend(tool_result)
            elif isinstance(tool_result, Exception):
                results.append({"error": str(tool_result)})

        return results

    async def run_notify(self, message: str, provider: str = "slack") -> dict:
        cmd = f"notify -data '{message}' -provider {provider}"
        output = await self.run_command(cmd)
        return {"notify_status": "sent", "output": output}

    def filter_vulnerabilities(self, vulnerabilities: list) -> list:
        """
        Filtruje podatności, ignorując te, które są czysto teoretyczne lub nieistotne.
        """
        filtered_vulns = []

        for vuln in vulnerabilities:
            if self._should_ignore_vulnerability(vuln):
                print(f"Ignoring vulnerability: {vuln.get('templateID', 'Unknown')} - {vuln.get('description', '')[:100]}...")
                continue
            filtered_vulns.append(vuln)

        return filtered_vulns

    def _should_ignore_vulnerability(self, vuln: dict) -> bool:
        """
        Sprawdza, czy podatność powinna być zignorowana na podstawie różnych kryteriów.
        """
        # Extract fields from different tool formats
        template_id = (vuln.get("templateID") or vuln.get("name") or "").lower()
        description = (vuln.get("description") or vuln.get("cmseek_finding") or
                      vuln.get("arachni_finding") or vuln.get("zap_finding") or "").lower()
        severity = vuln.get("severity", "").lower()

        # Handle different tool formats
        if "cmseek_finding" in vuln:
            description = vuln["cmseek_finding"].lower()
        elif "arachni_finding" in vuln:
            description = vuln["arachni_finding"].lower()
        elif "zap_finding" in vuln:
            description = vuln["zap_finding"].lower()

        # 1. Luki czysto teoretyczne, bez realnego scenariusza ataku
        if self.filter_config["ignore_theoretical"] and any(keyword in description for keyword in [
            "theoretical", "academic", "proof of concept", "poc only",
            "no practical impact", "no real impact", "minimal impact"
        ]):
            return True

        # 2. Błędy wymagające nieprawdopodobnej interakcji użytkownika (np. self-XSS)
        if self.filter_config["ignore_self_xss"] and any(keyword in template_id or keyword in description for keyword in [
            "self-xss", "self-xss", "user-controlled", "user-input",
            "requires user interaction", "victim interaction required"
        ]):
            return True

        # 3. Ujawnianie wersji oprogramowania lub banerów (bez dodatkowego wpływu)
        if self.filter_config["ignore_version_disclosure"] and any(keyword in template_id for keyword in [
            "version-disclosure", "banner-disclosure", "server-version",
            "software-version", "header-disclosure"
        ]) and "information disclosure" in description and severity in ["info", "low"]:
            return True

        # 4. Brak flag "Secure" i "HttpOnly" na ciasteczkach (bez udowodnionego wektora ataku)
        if self.filter_config["ignore_cookie_flags"] and any(keyword in template_id for keyword in [
            "cookie-secure-flag", "cookie-httponly", "cookie-flags",
            "secure-cookie", "httponly-cookie"
        ]) and severity in ["info", "low"]:
            return True

        # 5. Clickjacking na stronach bez wrażliwych akcji
        if self.filter_config["ignore_clickjacking"] and "clickjacking" in template_id and any(keyword in description for keyword in [
            "no sensitive actions", "no critical functions", "static page",
            "no user input", "read-only"
        ]):
            return True

        # 6. CSRF na formularzach bez istotnych działań (np. wylogowanie)
        if self.filter_config["ignore_csrf"] and "csrf" in template_id and any(keyword in description for keyword in [
            "logout", "sign-out", "log out", "non-critical",
            "no sensitive data", "no financial impact"
        ]):
            return True

        # 7. Otwarte przekierowania (Open Redirect) bez pokazania dodatkowego zagrożenia
        if self.filter_config["ignore_open_redirect"] and any(keyword in template_id for keyword in [
            "open-redirect", "url-redirect", "redirect"
        ]) and severity in ["info", "low"] and "no additional impact" in description:
            return True

        # 8. Brak mechanizmów SPF, DKIM, DMARC (jako pojedynczy błąd)
        if self.filter_config["ignore_email_security"] and any(keyword in template_id for keyword in [
            "spf-missing", "dkim-missing", "dmarc-missing",
            "email-spf", "email-dkim", "email-dmarc"
        ]) and severity in ["info", "low"]:
            return True

        # 9. Większość problemów z brakiem limitowania zapytań (rate limiting)
        if self.filter_config["ignore_rate_limiting"] and any(keyword in template_id for keyword in [
            "rate-limit", "rate-limiting", "brute-force", "enumeration"
        ]) and severity in ["info", "low"] and "no rate limiting" in description:
            return True

        # 10. Ataki wymagające fizycznego dostępu do urządzenia
        if self.filter_config["ignore_physical_access"] and any(keyword in description for keyword in [
            "physical access", "local access", "device access",
            "usb access", "hardware access", "requires physical"
        ]):
            return True

        # 11. Wyniki automatycznych skanerów bez ręcznej weryfikacji
        if self.filter_config["ignore_unverified_scans"] and any(keyword in description for keyword in [
            "automated scan", "scanner result", "unverified",
            "false positive", "needs manual verification"
        ]):
            return True

        # 12. Błędy w aplikacjach lub systemach, które nie są już wspierane (end-of-life)
        if self.filter_config["ignore_eol_systems"] and any(keyword in description for keyword in [
            "end-of-life", "eol", "unsupported", "deprecated",
            "no longer maintained", "obsolete"
        ]):
            return True

        # 13. Dodatkowe filtry dla powszechnych fałszywych pozytywów
        if self.filter_config["ignore_common_fp"] and template_id in [
            "tech-detect", "waf-detect", "server-info",
            "directory-listing", "backup-files", "git-config",
            "ds-store-file", "phpinfo", "server-status"
        ] and severity in ["info", "low"]:
            return True

        return False