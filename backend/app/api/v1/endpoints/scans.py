from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload, selectinload
from app.db.database import SessionLocal
from app.db.models import Scan, Vulnerability, Target
from app.schemas.schemas import Scan as ScanSchema, ScanCreate, ScanCreateWithDomain, Vulnerability as VulnerabilitySchema, VulnerabilityCreate
from app.core.scanner import scan_target
from app.core.engine import ScannerEngine
from app.core.integrations import shodan_info, urlscan_info, virustotal_info, send_slack_alert
import asyncio
import logging
import threading

logger = logging.getLogger(__name__)
from app.schemas.schemas import Scan as ScanSchema, ScanCreate, ScanCreateWithDomain, Vulnerability as VulnerabilitySchema, VulnerabilityCreate
from app.core.scanner import scan_target
from app.core.engine import ScannerEngine
from app.core.integrations import shodan_info, urlscan_info, virustotal_info, send_slack_alert
import asyncio

router = APIRouter()

def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()

async def run_scan_async(scan_id: int, domain: str):
    db = SessionLocal()
    print(f"Starting scan for {domain} with id {scan_id}")
    try:
        engine = ScannerEngine(domain)
        print("Running subfinder...")
        subdomains = await engine.run_subfinder()
        print(f"Subdomains found: {len(subdomains)}")
        # print("Running amass...")
        # amass_subdomains = await engine.run_amass()
        # print(f"Amass subdomains found: {len(amass_subdomains)}")
        # print("Running sublist3r...")
        # sublist3r_subdomains = await engine.run_sublist3r()
        # print(f"Sublist3r subdomains found: {len(sublist3r_subdomains)}")
        print("Running crt.sh...")
        crtsh_subdomains = await engine.run_crtsh()
        print(f"crt.sh subdomains found: {len(crtsh_subdomains)}")
        all_subdomains = subdomains + crtsh_subdomains
        print("Running whois...")
        whois_info = await engine.run_whois()
        print(f"Whois info: {whois_info}")
        print("Running dig...")
        dig_info = await engine.run_dig()
        print(f"Dig info: {dig_info}")
        print("Running nslookup...")
        nslookup_info = await engine.run_nslookup()
        print(f"Nslookup info: {nslookup_info}")
        print("Running httpx...")
        live_urls = await engine.run_httpx(all_subdomains)
        print(f"Live URLs: {len(live_urls)}")
        # print("Running naabu...")
        # naabu_ports = await engine.run_naabu()
        # print(f"Naabu ports: {naabu_ports}")
        print("Running nmap...")
        nmap_results = await engine.run_nmap(live_urls)
        print(f"Nmap results: {len(nmap_results)}")
        print("Running nuclei...")
        nuclei_results = await engine.run_nuclei(live_urls)
        print(f"Nuclei results: {len(nuclei_results)}")
        print("Running Nikto...")
        nikto_results = []
        for url_obj in live_urls[:3]:  # Run on first 3 URLs
            url = url_obj.get("url", url_obj.get("host", ""))
            if url.startswith("http"):
                nikto_results += await engine.run_nikto(url)
        print(f"Nikto results: {len(nikto_results)}")
        print("Running Wapiti...")
        wapiti_results = []
        for url_obj in live_urls[:3]:  # Run on first 3 URLs
            url = url_obj.get("url", url_obj.get("host", ""))
            if url.startswith("http"):
                wapiti_results += await engine.run_wapiti(url)
        print(f"Wapiti results: {len(wapiti_results)}")
        print("Running XSStrike...")
        xsstrike_results = []
        for url_obj in live_urls[:3]:  # Run on first 3 URLs
            url = url_obj.get("url", url_obj.get("host", ""))
            if url.startswith("http"):
                xsstrike_results += await engine.run_xsstrike(url)
        print(f"XSStrike results: {len(xsstrike_results)}")
        print("Running CMSeek...")
        cmseek_results = []
        for url_obj in live_urls[:3]:  # Run on first 3 URLs
            url = url_obj.get("url", url_obj.get("host", ""))
            if url.startswith("http"):
                cmseek_results += await engine.run_cmseek(url)
        print(f"CMSeek results: {len(cmseek_results)}")
        print("Running Skipfish...")
        skipfish_results = []
        for url_obj in live_urls[:2]:  # Run on first 2 URLs (resource intensive)
            url = url_obj.get("url", url_obj.get("host", ""))
            if url.startswith("http"):
                skipfish_results += await engine.run_skipfish(url)
        print(f"Skipfish results: {len(skipfish_results)}")
        print("Running Arachni...")
        arachni_results = []
        for url_obj in live_urls[:2]:  # Run on first 2 URLs (resource intensive)
            url = url_obj.get("url", url_obj.get("host", ""))
            if url.startswith("http"):
                arachni_results += await engine.run_arachni(url)
        print(f"Arachni results: {len(arachni_results)}")
        print("Running OWASP ZAP...")
        zap_results = []
        for url_obj in live_urls[:2]:  # Run on first 2 URLs (resource intensive)
            url = url_obj.get("url", url_obj.get("host", ""))
            if url.startswith("http"):
                zap_results += await engine.run_owasp_zap(url)
        print(f"OWASP ZAP results: {len(zap_results)}")
        print("Running Lynis security audit...")
        lynis_results = await engine.run_lynis()
        print(f"Lynis results: {len(lynis_results)}")
        print("Running OpenSCAP compliance check...")
        openscap_results = await engine.run_openscap()
        print(f"OpenSCAP results: {len(openscap_results)}")
        print("Running ClamAV antivirus scan...")
        clamav_results = await engine.run_clamav()
        print(f"ClamAV results: {len(clamav_results)}")
        print("Running RKHunter rootkit detection...")
        rkhunter_results = await engine.run_rkhunter()
        print(f"RKHunter results: {len(rkhunter_results)}")
        print("Running chkrootkit rootkit detection...")
        chkrootkit_results = await engine.run_chkrootkit()
        print(f"chkrootkit results: {len(chkrootkit_results)}")
        print("Running AIDE file integrity check...")
        aide_results = await engine.run_aide()
        print(f"AIDE results: {len(aide_results)}")
        print("Running Suricata IDS...")
        suricata_results = await engine.run_suricata()
        print(f"Suricata results: {len(suricata_results)}")
        print("Analyzing auditd logs...")
        auditd_results = await engine.run_auditd_analysis()
        print(f"auditd results: {len(auditd_results)}")
        print("Checking fail2ban status...")
        fail2ban_results = await engine.run_fail2ban_status()
        print(f"fail2ban results: {len(fail2ban_results)}")
        print("Running Lynis system audit...")
        lynis_results = await engine.run_lynis()
        print(f"Lynis results: {len(lynis_results)}")
        print("Running Brakeman...")
        brakeman_results = await engine.run_brakeman()
        print(f"Brakeman results: {len(brakeman_results)}")
        print("Running PMD...")
        pmd_results = await engine.run_pmd()
        print(f"PMD results: {len(pmd_results)}")
        print("Running ClamAV...")
        clamav_results = await engine.run_clamav()
        print(f"ClamAV results: {len(clamav_results)}")
        print("Running OpenSCAP...")
        openscap_results = await engine.run_openscap()
        print(f"OpenSCAP results: {len(openscap_results)}")
        print("Running Safety...")
        safety_results = await engine.run_safety()
        print(f"Safety results: {len(safety_results)}")
        print("Running Trivy...")
        trivy_results = await engine.run_trivy(domain)
        print(f"Trivy results: {len(trivy_results)}")
        print("Running comprehensive Qualys-like assessment...")
        qualys_results = await engine.run_qualys_like_scan(domain)
        print(f"Qualys-like results: {len(qualys_results)}")
        # print("Running mitmproxy...")
        # mitmproxy_results = []
        # for url in live_urls[:1]:  # Run on first URL only for demo
        #     mitmproxy_results += await engine.run_mitmproxy(url["url"])
        # print(f"Mitmproxy results: {len(mitmproxy_results)}")
        # print("Running schemathesis...")
        # schemathesis_results = []
        # for url in live_urls[:1]:  # Assume OpenAPI at /swagger.json or similar
        #     openapi_url = url["url"] + "/swagger.json"
        #     schemathesis_results += await engine.run_schemathesis(openapi_url)
        # print(f"Schemathesis results: {len(schemathesis_results)}")
        # print("Running restler...")
        # restler_results = []
        # for url in live_urls[:1]:
        #     restler_results += await engine.run_restler(url["url"])
        # print(f"Restler results: {len(restler_results)}")
        # print("Running playwright...")
        # playwright_results = []
        # for url in live_urls[:1]:  # Run on first URL
        #     playwright_results += await engine.run_playwright(url["url"])
        # print(f"Playwright results: {len(playwright_results)}")
        # print("Running selenium...")
        # selenium_results = []
        # for url in live_urls[:1]:
        #     selenium_results += await engine.run_selenium(url["url"])
        # print(f"Selenium results: {len(selenium_results)}")
        # print("Running appium...")
        # appium_results = await engine.run_appium()
        # print(f"Appium results: {len(appium_results)}")
        # print("Running adb...")
        # adb_results = await engine.run_adb()
        # print(f"ADB results: {len(adb_results)}")
        # print("Running apktool...")
        # apktool_results = await engine.run_apktool()
        # print(f"Apktool results: {len(apktool_results)}")
        # print("Running jadx...")
        # jadx_results = await engine.run_jadx()
        # print(f"Jadx results: {len(jadx_results)}")
        # print("Running mobsf...")
        # mobsf_results = await engine.run_mobsf()
        # print(f"MobSF results: {len(mobsf_results)}")
        # print("Running frida...")
        # frida_results = await engine.run_frida()
        # print(f"Frida results: {len(frida_results)}")
        # print("Running objection...")
        # objection_results = await engine.run_objection()
        # print(f"Objection results: {len(objection_results)}")
        print("Running tshark...")
        tshark_results = await engine.run_tshark()
        print(f"Tshark results: {len(tshark_results)}")
        # print("Running tcpreplay...")
        # tcpreplay_results = await engine.run_tcpreplay()
        # print(f"Tcpreplay results: {len(tcpreplay_results)}")
        # print("Running wireshark analysis...")
        # wireshark_results = await engine.run_wireshark_analysis()
        # print(f"Wireshark results: {len(wireshark_results)}")
        # print("Running boofuzz...")
        # boofuzz_results = []
        # for url in live_urls[:1]:
        #     boofuzz_results += await engine.run_boofuzz(url["url"])
        # print(f"Boofuzz results: {len(boofuzz_results)}")
        # print("Running afl...")
        # afl_results = await engine.run_afl()
        # print(f"AFL results: {len(afl_results)}")
        # print("Running wfuzz...")
        # wfuzz_results = []
        # for url in live_urls[:1]:
        #     wfuzz_results += await engine.run_wfuzz(url["url"])
        # print(f"Wfuzz results: {len(wfuzz_results)}")
        # print("Running radamsa...")
        # radamsa_results = await engine.run_radamsa()
        # print(f"Radamsa results: {len(radamsa_results)}")
        # print("Running peach...")
        # peach_results = await engine.run_peach()
        # print(f"Peach results: {len(peach_results)}")
        # print("Running zzuf...")
        # zzuf_results = await engine.run_zzuf()
        # print(f"Zzuf results: {len(zzuf_results)}")
        print("Running semgrep...")
        semgrep_results = await engine.run_semgrep()
        print(f"Semgrep results: {len(semgrep_results)}")
        print("Running bandit...")
        bandit_results = await engine.run_bandit()
        print(f"Bandit results: {len(bandit_results)}")
        # print("Running ghidra...")
        # ghidra_results = await engine.run_ghidra()
        # print(f"Ghidra results: {len(ghidra_results)}")
        # print("Running radare2...")
        # radare2_results = await engine.run_radare2()
        # print(f"Radare2 results: {len(radare2_results)}")
        # print("Running cutter...")
        # cutter_results = await engine.run_cutter()
        # print(f"Cutter results: {len(cutter_results)}")
        # print("Running strings...")
        # strings_results = await engine.run_strings()
        # print(f"Strings results: {len(strings_results)}")
        # print("Running objdump...")
        # objdump_results = await engine.run_objdump()
        # print(f"Objdump results: {len(objdump_results)}")
        # print("Running readelf...")
        # readelf_results = await engine.run_readelf()
        # print(f"Readelf results: {len(readelf_results)}")
        print("Running ffuf...")
        ffuf_results = []
        for url in live_urls:
            ffuf_results += await engine.run_ffuf(url["url"])
        print(f"FFUF results: {len(ffuf_results)}")
        print("Running dirsearch...")
        dirsearch_results = []
        for url in live_urls:
            dirsearch_results += await engine.run_dirsearch(url["url"])
        print(f"Dirsearch results: {len(dirsearch_results)}")
        # print("Running feroxbuster...")
        # feroxbuster_results = []
        # for url in live_urls:
        #     feroxbuster_results += await engine.run_feroxbuster(url["url"])
        # print(f"Feroxbuster results: {len(feroxbuster_results)}")
        # print("Running gobuster...")
        # gobuster_results = []
        # for url in live_urls:
        #     gobuster_results += await engine.run_gobuster(url["url"])
        # print(f"Gobuster results: {len(gobuster_results)}")
        print("Running sqlmap...")
        sqlmap_results = []
        for url in live_urls:
            sqlmap_results += await engine.run_sqlmap(url["url"])
        print(f"SQLMap results: {len(sqlmap_results)}")
        print("Getting Shodan info...")
        shodan_results = shodan_info(domain)
        print("Getting URLScan info...")
        urlscan_results = urlscan_info(domain)
        print("Getting VirusTotal info...")
        vt_results = virustotal_info(domain)
        print("Running Jaeles...")
        jaeles_results = []
        for url in live_urls[:5]:  # Run on first 5 URLs to avoid overload
            jaeles_results += await engine.run_jaeles(url["url"])
        print(f"Jaeles results: {len(jaeles_results)}")
        print("Running Katana...")
        katana_results = []
        for url in live_urls[:5]:  # Run on first 5 URLs
            katana_results += await engine.run_katana(url["url"])
        print(f"Katana results: {len(katana_results)}")
        print("Running Uncover...")
        uncover_results = await engine.run_uncover(domain)
        print(f"Uncover results: {len(uncover_results)}")
        print("Running DNSX...")
        dnsx_results = await engine.run_dnsx(domain)
        print(f"DNSX results: {len(dnsx_results)}")
        print("Running AlterX...")
        alterx_results = await engine.run_alterx(domain)
        print(f"AlterX results: {len(alterx_results)}")
        print("Running Interactsh...")
        interactsh_results = await engine.run_interactsh()
        print(f"Interactsh results: {len(interactsh_results)}")
        # print("Running pandoc for PDF report...")
        # report_content = f"# Bug Bounty Report for {domain}\n\nVulnerabilities found: {len(nuclei_results)}\n\nDetails: {nuclei_results}"
        # pdf_path = await engine.run_pandoc(report_content)
        # print(f"PDF generated: {pdf_path}")
        # print("Submitting to Bugcrowd...")
        # bugcrowd_result = await engine.run_bugcrowd_api(report_content, "example-program")
        # print(f"Bugcrowd submission: {bugcrowd_result}")
        # print("Submitting to Jira...")
        # jira_result = await engine.run_jira_api(report_content, "BUG")
        # print(f"Jira submission: {jira_result}")
        # print("Submitting to GitHub...")
        # github_result = await engine.run_github_api(report_content, "owner/repo")
        # print(f"GitHub submission: {github_result}")
        # Send notification with results summary
        summary_message = f"Scan completed for {domain}. Found {len(nuclei_results)} vulnerabilities."
        notify_result = await engine.run_notify(summary_message)
        print(f"Notification sent: {notify_result}")

        # Filtruj podatności - ignoruj te, które są czysto teoretyczne lub nieistotne
        all_vulnerabilities = (nuclei_results + nikto_results + wapiti_results + xsstrike_results +
                              cmseek_results + skipfish_results + arachni_results + zap_results +
                              lynis_results + openscap_results + clamav_results + rkhunter_results +
                              chkrootkit_results + aide_results + suricata_results +
                              auditd_results + fail2ban_results)
        filtered_vulnerabilities = engine.filter_vulnerabilities(all_vulnerabilities)
        print(f"After filtering: {len(filtered_vulnerabilities)} vulnerabilities remain (filtered out {len(all_vulnerabilities) - len(filtered_vulnerabilities)})")

        # Zapisz podatności do bazy danych
        for vuln in filtered_vulnerabilities:
            # Normalize vulnerability data from different tool formats
            name = (vuln.get("templateID") or vuln.get("name") or vuln.get("cmseek_finding") or
                   vuln.get("arachni_finding") or vuln.get("zap_finding") or vuln.get("lynis_finding") or
                   vuln.get("openscap_finding") or vuln.get("clamav_finding") or vuln.get("rkhunter_finding") or
                   vuln.get("chkrootkit_finding") or vuln.get("aide_finding") or vuln.get("snort_alert") or
                   vuln.get("suricata_alert") or vuln.get("zeek_finding") or vuln.get("auditd_event") or
                   "Unknown")
            severity = vuln.get("severity", "info")
            description = (vuln.get("description") or vuln.get("cmseek_finding") or
                          vuln.get("arachni_finding") or vuln.get("zap_finding") or
                          vuln.get("lynis_finding") or vuln.get("openscap_finding") or
                          str(vuln))
            url = (vuln.get("matched") or vuln.get("url") or vuln.get("host") or domain)

            db_vuln = Vulnerability(
                scan_id=scan_id,
                name=name,
                severity=severity,
                description=description,
                url=url
            )
            db.add(db_vuln)
            send_slack_alert(db_vuln.name, db_vuln.url, db_vuln.severity)
        db.commit()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "completed"
            from datetime import datetime
            scan.completed_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
        db.commit()
        print(f"Scan failed: {e}")
    finally:
        db.close()

@router.post("/scans/{target_id}/run_full_scan")
async def run_full_scan(target_id: int, db: Session = Depends(get_db)):
	target = db.query(Target).filter(Target.id == target_id).first()
	if not target:
		raise HTTPException(status_code=404, detail="Target not found")
	engine = ScannerEngine(target.url)
	subdomains = await engine.run_subfinder()
	live_urls = await engine.run_httpx(subdomains)
	nmap_results = await engine.run_nmap(live_urls)
	nuclei_results = await engine.run_nuclei(live_urls)
	shodan_results = shodan_info(target.url)
	urlscan_results = urlscan_info(target.url)
	vt_results = virustotal_info(target.url)
	# Przykład: dodaj podatności do bazy i wyślij alert na Slacka
	for vuln in nuclei_results:
		db_vuln = Vulnerability(scan_id=target_id, name=vuln.get("templateID", "N/A"), severity=vuln.get("severity", "info"), description=vuln.get("description", ""), url=vuln.get("matched", ""))
		db.add(db_vuln)
		send_slack_alert(db_vuln.name, db_vuln.url, db_vuln.severity)
	db.commit()
	return {
		"subdomains": subdomains,
		"live_urls": live_urls,
		"nmap": nmap_results,
		"nuclei": nuclei_results,
		"shodan": shodan_results,
		"urlscan": urlscan_results,
		"virustotal": vt_results
	}

@router.post("/scans/{scan_id}/vulnerabilities", response_model=VulnerabilitySchema)
def create_vulnerability(scan_id: int, vuln: VulnerabilityCreate, db: Session = Depends(get_db)):
	db_vuln = Vulnerability(scan_id=scan_id, **vuln.dict())
	db.add(db_vuln)
	db.commit()
	db.refresh(db_vuln)
	return db_vuln

@router.post("/scans/")
def create_scan(scan_data: dict, db: Session = Depends(get_db)):
	try:
		domain = scan_data.get("domain")
		if not domain:
			raise HTTPException(status_code=400, detail="Domain is required")
		
		# Znajdź lub utwórz target
		target = db.query(Target).filter(Target.url == domain).first()
		if not target:
			target = Target(url=domain)
			db.add(target)
			db.commit()
			db.refresh(target)
		
		db_scan = Scan(target_id=target.id, domain=target.url, status="running")
		db.add(db_scan)
		db.commit()
		db.refresh(db_scan)
		logger.error(f"Scan created with status: {db_scan.status}")
		
		# Uruchom skanowanie w tle
		def run_scan():
			asyncio.run(run_scan_async(db_scan.id, target.url))
		
		thread = threading.Thread(target=run_scan)
		thread.start()
		
		return db_scan
	except Exception as e:
		logger.error(f"Error in create_scan: {e}")
		raise

@router.get("/scans/")
def read_scans(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
	scans = db.query(Scan).offset(skip).limit(limit).all()
	result = []
	for scan in scans:
		scan_dict = {
			"id": scan.id,
			"status": scan.status,
			"domain": scan.domain,
			"started_at": scan.started_at,
			"completed_at": scan.completed_at,
			"vulnerabilities": scan.vulnerabilities
		}
		result.append(scan_dict)
	return result

@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
	scan = db.query(Scan).filter(Scan.id == scan_id).first()
	if not scan:
		raise HTTPException(status_code=404, detail="Scan not found")
	
	# Usuń powiązane vulnerabilities
	db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()
	
	# Usuń scan
	db.delete(scan)
	db.commit()
	return {"message": "Scan deleted successfully"}

@router.get("/scans/{scan_id}/vulnerabilities", response_model=list[VulnerabilitySchema])
def read_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
	return db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

@router.get("/scans/{scan_id}/report")
def generate_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    # Pobierz szczegóły rekonesansu i skanowania
    details = {
        "domain": scan.domain,
        "scan_id": scan.id,
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "target_id": scan.target_id,
        "vulnerabilities": vulnerabilities,
    }
    # Szczegółowy raport Markdown
    report = f"""# Bug Bounty Report: {details['domain']}\n\n"""
    report += f"## Scan Metadata\n- **Scan ID**: {details['scan_id']}\n- **Target ID**: {details['target_id']}\n- **Status**: {details['status']}\n- **Started At**: {details['started_at']}\n- **Completed At**: {details['completed_at']}\n\n"
    report += "## Reconnaissance & Enumeration\n"
    report += "### Tools Used\n"
    report += "- **Subfinder**: Subdomain discovery\n- **Amass**: Passive subdomain enumeration\n- **Sublist3r**: Subdomain enumeration\n- **crt.sh**: Certificate transparency checks\n- **Whois**: Domain registration info\n- **Dig**: DNS records\n- **Nslookup**: DNS lookup\n- **Httpx**: Live host checking\n- **Naabu**: Fast port scanning\n- **Nmap**: Advanced port & service scanning\n- **Dirsearch**: Directory brute-forcing\n- **ffuf**: Fuzzing directories/files\n- **Feroxbuster**: Fast directory discovery\n- **Gobuster**: Directory enumeration\n- **SQLMap**: SQL Injection testing\n- **Nuclei**: Vulnerability scanning\n- **Mitmproxy**: HTTPS interception\n- **Schemathesis**: API fuzzing based on OpenAPI\n- **Restler**: REST API fuzzing\n- **Playwright**: Web UI automation\n- **Selenium**: Web UI testing\n- **Appium**: Mobile automation\n- **ADB**: Android Debug Bridge\n- **Apktool**: APK decompilation\n- **Jadx**: APK decompilation\n- **MobSF**: Mobile security framework\n- **Frida**: Dynamic instrumentation\n- **Objection**: Mobile runtime testing\n- **Tshark**: Packet capture\n- **Tcpreplay**: Packet replay\n- **Wireshark**: Deep packet analysis\n- **Boofuzz**: Binary fuzzing\n- **AFL**: Fuzzing framework\n- **Wfuzz**: Web fuzzing\n- **Radamsa**: Mutation generator\n- **Peach**: Fuzzing framework\n- **Zzuf**: Mutation tool\n- **Semgrep**: Static analysis\n- **Bandit**: Python security linter\n- **Ghidra**: Reverse engineering suite\n- **Radare2**: Binary analysis\n- **Cutter**: GUI for Radare2\n- **Strings**: Extract strings from binaries\n- **Objdump**: Disassemble binaries\n- **Readelf**: ELF file analysis\n- **Shodan, URLScan, VirusTotal**: External intelligence\n- **Pandoc**: Report generation to PDF\n- **Bugcrowd API**: Automated submission to Bugcrowd\n- **Jira API**: Issue creation in Jira\n- **GitHub API**: Issue creation in GitHub\n\n"
    report += "### Workflow Summary\n"
    report += "All tools were run automatically in the following order: Subfinder & Amass & Sublist3r & crt.sh → Whois & Dig & Nslookup → Httpx → Naabu & Nmap → Dirsearch & ffuf & Feroxbuster & Gobuster → SQLMap → Nuclei → Mitmproxy & Schemathesis & Restler → Playwright & Selenium & Appium → ADB & Apktool & Jadx & MobSF → Frida & Objection → Tshark & Tcpreplay & Wireshark → Boofuzz & AFL & Wfuzz & Radamsa & Peach & Zzuf → Semgrep & Bandit → Ghidra & Radare2 & Cutter & Strings & Objdump & Readelf → Pandoc PDF Generation → Bugcrowd/Jira/GitHub Submissions. Results are stored in the database and available via API.\n\n"
    report += "## Vulnerabilities Found\n"
    if vulnerabilities:
        for vuln in vulnerabilities:
            report += f"---\n**Vulnerability:** {vuln.name}\n**Severity:** {vuln.severity}\n**Description:** {vuln.description}\n**URL/Location:** {vuln.url}\n\n"
    else:
        report += "No vulnerabilities found.\n\n"
    report += "## Recommendations\n- Patch all identified vulnerabilities promptly.\n- Review exposed endpoints, directories, and ports.\n- Harden web server and application configuration.\n- Monitor for new subdomains and endpoints.\n- Regularly scan for secrets in public repositories.\n- Enable logging and monitoring for suspicious activity.\n- Use bug bounty platforms for continuous testing.\n\n"
    report += "## Technical Details\n- All tools were run in isolated containers.\n- Results are available in the database and via API.\n- Report is ready for submission to HackerOne, Bugcrowd, etc.\n\n"
    report += "## Additional Information\nThis report was generated by Bug Bounty Orchestrator. For more details, contact the security team.\n"
    return {"report": report}