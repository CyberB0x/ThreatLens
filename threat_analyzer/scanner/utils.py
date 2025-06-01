import hashlib, whois, requests, yara
from django.conf import settings

def calculate_sha256(file):
    h = hashlib.sha256()
    for chunk in file.chunks():
        h.update(chunk)
    return h.hexdigest()

def analyze_with_virustotal(sha256=None, url=None):
    headers = {"x-apikey": settings.VT_API_KEY}
    if url:
        response = requests.post("https://www.virustotal.com/api/v3/urls",
                                 headers=headers, data={"url": url})
        return response.json()
    if sha256:
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                headers=headers)
        return response.json()
    return {}

def ip_reputation(ip):
    # Место для подключения внешней API или MaxMind
    return {"dummy": "ip info"}

def get_whois(domain_or_ip):
    try:
        return whois.whois(domain_or_ip)
    except Exception as e:
        return {"error": str(e)}

def run_yara(file_path):
    try:
        rules = yara.compile(filepath="scanner/yara_rules/example.yar")
        matches = rules.match(filepath=file_path)
        return str(matches)
    except Exception as e:
        return f"YARA error: {e}"
