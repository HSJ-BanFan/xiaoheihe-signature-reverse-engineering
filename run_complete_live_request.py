"""Test real request to XiaoHeiHe core forum endpoint using local signature service."""
import subprocess
import time
import json
import urllib.request
import urllib.parse
import ssl

JAR_PATH = "cases/case-2026-apk01/working/xiaoheihe-signer.jar"
PORT = 8089

print("[*] 1. Launching background signature microservice on port", PORT)
proc = subprocess.Popen(
    ["java", "-jar", JAR_PATH, "--server", str(PORT)],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

time.sleep(3)

try:
    # Target endpoint: core game forum post list (e.g., PUBG / General Game feed)
    target_path = "/bbs/app/feeds/news"
    print(f"[*] 2. Querying signature microservice for endpoint: {target_path}")
    
    sign_url = f"http://127.0.0.1:{PORT}/sign?path={urllib.parse.quote(target_path)}"
    req = urllib.request.urlopen(sign_url, timeout=10)
    sign_data = json.loads(req.read().decode("utf-8"))
    print("[+] Signature Microservice Response:")
    print(json.dumps(sign_data, indent=2, ensure_ascii=False))
    
    quad = sign_data["data"]
    
    # Complete 18-parameter protocol payload + business pagination
    params = {
        "offset": "0",
        "limit": "10",
        "heybox_id": "YOUR_HEYBOX_ID",
        "imei": "YOUR_IMEI",
        "device_info": "25102RKBEC",
        "os_type": "Android",
        "x_os_type": "Android",
        "x_client_type": "mobile",
        "os_version": "14",
        "version": "1.3.385",
        "build": "385",
        "channel": "heybox_xiaomi",
        "x_app": "heybox",
        "time_zone": "Asia/Shanghai",
        "dw": "2",
        "netmode": "wifi",
        "_time": quad["_time"],
        "nonce": quad["nonce"],
        "hkey": quad["hkey"],
        "_rnd": quad["_rnd"]
    }
    
    query_str = urllib.parse.urlencode(params)
    api_url = f"https://api.xiaoheihe.cn{target_path}?{query_str}"
    
    print("\n[*] 3. Dispatching live HTTP GET to XiaoHeiHe production server:")
    print("    URL:", api_url)
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    http_req = urllib.request.Request(
        api_url,
        headers={
            "User-Agent": "Mozilla/5.0 (Linux; Android 14; 25102RKBEC Build/UP1A.231005.007; wv) AppleWebKit/537.36",
            "Accept": "application/json",
            "Cookie": "pkey=YOUR_TEST_PKEY; heybox_id=76644009",
            "Referer": "https://api.xiaoheihe.cn",
            "Connection": "close"
        }
    )
    
    with urllib.request.urlopen(http_req, context=ctx, timeout=10) as resp:
        code = resp.status
        body = resp.read().decode("utf-8", errors="replace")
        print(f"\n[+] 4. Server Response (HTTP {code}):")
        
        parsed = json.loads(body)
        print("    Status Msg :", repr(parsed.get("msg")))
        print("    API Status :", repr(parsed.get("status")))
        
        links = parsed.get("result", {}).get("links", [])
        print(f"    Returned link/banner modules count: {len(links)}")
        for i, item in enumerate(links[:3]):
            banners = item.get("banners", [])
            for b in banners:
                print(f"      [{i+1}] Title: {b.get('title')} | Idea ID: {b.get('idea_id')}")

finally:
    proc.terminate()
    proc.wait()
    print("\n[*] 5. Signature microservice stopped cleanly.")

