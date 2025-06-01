from django.shortcuts import render, redirect
from .forms import SubmissionForm
from .models import Submission
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import hashlib
import requests
import time
import json
import yara
import os

@csrf_exempt
def clear_results(request):
    if request.method == "POST":
        Submission.objects.all().delete()
    return redirect("scanner:results")

def calculate_sha256(file_obj):
    sha256 = hashlib.sha256()
    for chunk in file_obj.chunks():
        sha256.update(chunk)
    return sha256.hexdigest()

def scan_with_virustotal(file_obj):
    upload_url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": settings.VT_API_KEY
    }

    file_obj.seek(0)
    files = {"file": (file_obj.name, file_obj.read())}
    upload_response = requests.post(upload_url, files=files, headers=headers)

    if upload_response.status_code != 200:
        return {"error": upload_response.text}

    file_id = upload_response.json().get("data", {}).get("id")
    if not file_id:
        return {"error": "No file ID from VirusTotal"}

    # Ждем анализа
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    for _ in range(10):
        analysis_response = requests.get(analysis_url, headers=headers)
        if analysis_response.status_code == 200:
            data = analysis_response.json()
            if data.get("data", {}).get("attributes", {}).get("status") == "completed":
                break
        time.sleep(3)
    else:
        return {"error": "Timeout waiting for analysis"}

    result_url = f"https://www.virustotal.com/api/v3/files/{data['meta']['file_info']['sha256']}"
    result_response = requests.get(result_url, headers=headers)
    if result_response.status_code == 200:
        return result_response.json()
    return {"error": result_response.text}

def scan_with_yara(file_obj):
    try:
        rule_path = os.path.join(settings.BASE_DIR, "scanner", "yara_rules", "index.yar")
        rules = yara.compile(filepath=rule_path)

        file_obj.seek(0)
        matches = rules.match(data=file_obj.read())

        return json.dumps([match.rule for match in matches]) if matches else json.dumps([])
    except Exception as e:
        return json.dumps({"error": str(e)})

def submit_view(request):
    if request.method == 'POST':
        form = SubmissionForm(request.POST, request.FILES)
        if form.is_valid():
            url = form.cleaned_data.get('url')
            file = form.cleaned_data.get('file')

            if url:
                submission = Submission.objects.create(
                    input_type='url',
                    value=url,
                    sha256=None,
                    vt_result=None,
                    yara_result=None
                )
            elif file:
                sha256_hash = calculate_sha256(file)
                vt_result = scan_with_virustotal(file)
                file.seek(0)
                yara_result = scan_with_yara(file)

                submission = Submission.objects.create(
                    input_type='file',
                    value=file.name,
                    sha256=sha256_hash,
                    vt_result=vt_result,
                    yara_result=yara_result
                )
            return redirect('scanner:results')
    else:
        form = SubmissionForm()

    return render(request, 'scanner/submit.html', {'form': form})

def results_view(request):
    submissions = Submission.objects.all().order_by("-created_at")
    query = request.GET.get("q")
    if query:
        submissions = submissions.filter(sha256__icontains=query)

    for scan in submissions:
        scan.is_malicious = False
        scan.yara_has_error = False

        if scan.vt_result:
            stats = scan.vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            scan.is_malicious = stats.get("malicious", 0) > 0

        yara_result_raw = scan.yara_result
        if yara_result_raw:
            if isinstance(yara_result_raw, str):
                try:
                    parsed = json.loads(yara_result_raw)
                    scan.yara_result = parsed
                except json.JSONDecodeError:
                    scan.yara_result = yara_result_raw
            else:
                scan.yara_result = yara_result_raw
        else:
            scan.yara_result = None

        yara_result_str = str(scan.yara_result or "").lower()
        scan.yara_has_error = "error" in yara_result_str or "fail" in yara_result_str

    return render(request, "scanner/results.html", {"submissions": submissions})
