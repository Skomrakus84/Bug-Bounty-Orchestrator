import requests
import os
import base64
import time
import json
from jira import JIRA
from github import Github

def shodan_info(target_ip: str):
    try:
        SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
        api_url = f"https://api.shodan.io/shodan/host/{target_ip}?key={SHODAN_API_KEY}"
        res = requests.get(api_url, timeout=10)
        res.raise_for_status()
        return res.json()
    except:
        return {}

def urlscan_info(target_url: str):
    try:
        URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")
        headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
        data = {"url": target_url, "visibility": "public"}
        submit_res = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data, timeout=10)
        submit_res.raise_for_status()
        submit_data = submit_res.json()
        time.sleep(5)  # shorter sleep
        result_url = submit_data['api']
        result_res = requests.get(result_url, timeout=10)
        result_res.raise_for_status()
        return result_res.json()
    except:
        return {}

def virustotal_info(target_url: str):
    try:
        VT_API_KEY = os.environ.get("VT_API_KEY")
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(api_url, headers=headers, timeout=10)
        res.raise_for_status()
        return res.json()
    except:
        return {}

def send_slack_alert(vulnerability_name, target_url, severity):
    SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
    if not SLACK_WEBHOOK_URL:
        return
    message = {
        "text": f"🚨 *Znaleziono nową podatność!* 🚨",
        "attachments": [
            {
                "color": "danger" if severity == "high" else "warning",
                "fields": [
                    {"title": "Nazwa podatności", "value": vulnerability_name, "short": True},
                    {"title": "URL", "value": target_url, "short": True},
                    {"title": "Poziom zagrożenia", "value": severity, "short": True}
                ]
            }
        ]
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=message, timeout=10)
    except:
        pass

def generate_pdf_report(markdown_content: str, output_path: str = "/tmp/report.pdf"):
    import subprocess
    try:
        with open("/tmp/report.md", "w") as f:
            f.write(markdown_content)
        subprocess.run(["pandoc", "/tmp/report.md", "-o", output_path], check=True)
        return output_path
    except Exception as e:
        print(f"Pandoc error: {e}")
        return None

def submit_to_bugcrowd(report_content: str, program_id: str):
    BUGCROWD_API_KEY = os.environ.get("BUGCROWD_API_KEY")
    if not BUGCROWD_API_KEY:
        return {"error": "No Bugcrowd API key"}
    try:
        headers = {"Authorization": f"Token {BUGCROWD_API_KEY}", "Content-Type": "application/json"}
        data = {"program": program_id, "title": "Automated Bug Bounty Report", "description": report_content}
        res = requests.post("https://api.bugcrowd.com/v1/submissions", headers=headers, json=data, timeout=10)
        res.raise_for_status()
        return res.json()
    except Exception as e:
        return {"error": str(e)}

def submit_to_jira(report_content: str, project_key: str):
    JIRA_SERVER = os.environ.get("JIRA_SERVER")
    JIRA_USER = os.environ.get("JIRA_USER")
    JIRA_PASSWORD = os.environ.get("JIRA_PASSWORD")
    if not all([JIRA_SERVER, JIRA_USER, JIRA_PASSWORD]):
        return {"error": "Missing Jira credentials"}
    try:
        jira = JIRA(server=JIRA_SERVER, basic_auth=(JIRA_USER, JIRA_PASSWORD))
        issue = jira.create_issue(project=project_key, summary="Bug Bounty Report", description=report_content, issuetype={'name': 'Bug'})
        return {"issue_key": issue.key}
    except Exception as e:
        return {"error": str(e)}

def submit_to_github(report_content: str, repo: str, title: str = "Bug Bounty Report"):
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        return {"error": "No GitHub token"}
    try:
        g = Github(GITHUB_TOKEN)
        repo_obj = g.get_repo(repo)
        issue = repo_obj.create_issue(title=title, body=report_content)
        return {"issue_number": issue.number}
    except Exception as e:
        return {"error": str(e)}