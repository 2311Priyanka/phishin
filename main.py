from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, unquote
import ipaddress, re, time, os
from pathlib import Path

app = FastAPI(title="Phishing Detection API", version="0.1.0")

# Local hackathon prototype. Restrict CORS before deploying publicly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

class ScanRequest(BaseModel):
    email_text: str = Field(default="", max_length=200_000)
    url: str = Field(default="", max_length=8_000)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at"
}
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
URGENT_RE = re.compile(
    r'\b(urgent|immediately|verify your account|password expires|suspended|'
    r'click here|unusual activity|confirm your password|account locked)\b',
    re.IGNORECASE
)
CREDENTIAL_RE = re.compile(
    r'\b(password|login|log in|sign in|credentials|one[- ]time password|OTP|bank details)\b',
    re.IGNORECASE
)

def inspect_url(raw_url: str):
    findings = []
    raw_url = raw_url.strip().rstrip(".,);]")
    if not raw_url:
        return {"url": "", "findings": findings, "score": 0}

    candidate = raw_url if re.match(r"^https?://", raw_url, re.I) else "https://" + raw_url
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            findings.append({"severity": "high", "code": "INVALID_URL", "message": "The URL could not be parsed safely."})
            return {"url": raw_url, "findings": findings, "score": 15}
        if parsed.username or parsed.password:
            findings.append({"severity": "high", "code": "USERINFO_IN_URL", "message": "The URL contains username/password fields before the host, a common deception technique."})
        try:
            ipaddress.ip_address(host)
            findings.append({"severity": "medium", "code": "IP_HOST", "message": "The destination uses a raw IP address instead of a conventional domain name."})
        except ValueError:
            pass
        if host in SHORTENERS:
            findings.append({"severity": "medium", "code": "SHORTENER", "message": "This is a URL-shortening domain; the final destination is not visible from the link alone."})
        if host.startswith("xn--") or ".xn--" in host:
            findings.append({"severity": "medium", "code": "PUNYCODE", "message": "The domain contains an internationalized/punycode label that may conceal lookalike characters."})
        decoded = unquote(raw_url)
        if decoded != raw_url:
            findings.append({"severity": "low", "code": "ENCODED_URL", "message": "The URL contains percent-encoded characters. Encoding is not inherently malicious, but it warrants inspection."})
        if "@" in parsed.netloc:
            findings.append({"severity": "medium", "code": "AT_SIGN", "message": "An @ symbol appears in the authority section and can make the actual destination confusing."})
        if host.count(".") >= 4:
            findings.append({"severity": "low", "code": "DEEP_SUBDOMAINS", "message": "The host has many subdomain levels; verify which registered domain you are visiting."})
        if len(raw_url) > 180:
            findings.append({"severity": "low", "code": "LONG_URL", "message": "The URL is unusually long and may hide meaningful parameters."})
        if parsed.scheme.lower() != "https":
            findings.append({"severity": "low", "code": "NO_HTTPS", "message": "The URL does not use HTTPS. This alone does not prove phishing."})
        score_map = {"high": 25, "medium": 15, "low": 7}
        score = min(65, sum(score_map.get(f["severity"], 0) for f in findings))
        return {"url": raw_url, "host": host, "findings": findings, "score": score}
    except Exception:
        return {"url": raw_url, "findings": [{"severity": "low", "code": "PARSE_ERROR", "message": "Could not fully parse this URL."}], "score": 5}

def analyze_email(text: str, extra_url: str = ""):
    start = time.perf_counter()
    findings = []
    urls = URL_RE.findall(text or "")
    if extra_url.strip():
        urls.append(extra_url.strip())
    # Keep unique URLs; do not fetch or open them.
    urls = list(dict.fromkeys(u.rstrip(".,);]") for u in urls))[:50]

    if URGENT_RE.search(text or ""):
        findings.append({"severity": "medium", "code": "URGENCY_LANGUAGE", "message": "Urgent or threatening language appears in the message. This is a signal, not proof of phishing."})
    if CREDENTIAL_RE.search(text or ""):
        findings.append({"severity": "low", "code": "CREDENTIAL_LANGUAGE", "message": "The message mentions passwords, sign-in, OTPs, or credentials. Check whether the request is expected."})
    if re.search(r'\b(gift card|wire transfer|crypto wallet|payment failed|invoice attached)\b', text or "", re.I):
        findings.append({"severity": "medium", "code": "PAYMENT_OR_BAIT", "message": "The message includes payment, invoice, or reward-related language often seen in social engineering."})
    if not urls and not (text or "").strip():
        findings.append({"severity": "low", "code": "EMPTY_INPUT", "message": "No email text or URL was provided."})

    url_results = [inspect_url(u) for u in urls]
    all_findings = findings + [f for result in url_results for f in result["findings"]]
    weights = {"high": 25, "medium": 15, "low": 7}
    score = min(100, sum(weights.get(f["severity"], 0) for f in all_findings))
    # Explicitly a heuristic demo: not a calibrated probability or a definitive verdict.
    if score >= 55:
        verdict = "HIGH RISK"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW SIGNALS DETECTED"
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    return {
        "verdict": verdict,
        "risk_score": score,
        "score_type": "heuristic indicator score, not a probability",
        "findings": all_findings,
        "urls": url_results,
        "url_count": len(url_results),
        "analysis_ms": elapsed_ms,
        "privacy": "This prototype does not intentionally persist submitted email content. Do not enable body logging or send sensitive content to third-party services.",
        "limitations": [
            "No live reputation lookup is configured.",
            "No trained ML classifier is configured.",
            "A low score does not guarantee that a message is safe."
        ]
    }

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "phishing-detection-api"}

@app.post("/api/scan")
def scan(req: ScanRequest):
    if not req.email_text.strip() and not req.url.strip():
        raise HTTPException(status_code=400, detail="Paste email content or enter a URL to scan.")
    return analyze_email(req.email_text, req.url)

@app.post("/api/scan-eml")
async def scan_eml(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Please upload an .eml file.")
    raw = await file.read()
    if len(raw) > 1_000_000:
        raise HTTPException(status_code=413, detail="File is too large (maximum 1 MB).")
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
        headers = "\n".join(f"{h}: {msg.get(h, '')}" for h in ("From", "Reply-To", "Return-Path", "Subject"))
        body = "\n".join(parts)
        result = analyze_email(headers + "\n\n" + body)
        result["email_headers"] = {
            "from": str(msg.get("From", "")),
            "reply_to": str(msg.get("Reply-To", "")),
            "subject": str(msg.get("Subject", ""))
        }
        return result
    except Exception:
        raise HTTPException(status_code=400, detail="Could not parse this .eml file.")

# Serve the frontend from the same local app.
app.mount("/", StaticFiles(directory=str(Path(__file__).parent / "static"), html=True), name="static")
