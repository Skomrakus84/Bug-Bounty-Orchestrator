# Scanner logic with Censys API integration

import os
import requests
from dotenv import load_dotenv
load_dotenv()

def scan_target(target: str) -> dict:
	censys_id = os.environ.get("CENSYS_API_ID")
	censys_secret = os.environ.get("CENSYS_API_SECRET")
	api_url = f"https://search.censys.io/api/v2/hosts/{target}"
	try:
		res = requests.get(api_url, auth=(censys_id, censys_secret))
		res.raise_for_status()
		data = res.json()
		services = [
			{"port": s["port"], "service_name": s.get("service_name", "N/A")}
			for s in data.get("result", {}).get("services", [])
		]
		return {"target": target, "status": "scanned", "services": services}
	except requests.exceptions.HTTPError as e:
		return {"target": target, "status": f"HTTP error: {e}"}
	except requests.exceptions.RequestException as e:
		return {"target": target, "status": f"Connection error: {e}"}