"""Multi-endpoint test for confirmed /bbs/app/ routes."""
import subprocess
import time
import json
import urllib.request
import urllib.parse
import ssl

JAR_PATH = "cases/case-2026-apk01/working/xiaoheihe-signer.jar"
PORT = 8089

print("[*] 1. Starting background signature microservice on port", PORT)
proc = subprocess.Popen(
    ["java", "-jar", JAR_PATH, "--server", str(PORT)],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)
time.sleep(3)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

test_suite = [
    {
        "name": "综合资讯列表 (feeds/news)",
        "path": "/bbs/app/feeds/news",
        "params": {"offset": "0", "limit": "5"}
    },
    {
        "name": "主推荐信息流 (feeds)",
        "path": "/bbs/app/feeds",
        "params": {"offset": "0", "limit": "5", "pull": "1"}
    },
    {
        "name": "话题信息流 (topic/feeds)",
        "path": "/bbs/app/topic/feeds",
        "params": {"offset": "0", "limit": "5", "topic_id": "1"}
    },
    {
        "name": "搜索热词 (search/hot_words)",
        "path": "/bbs/app/api/search/hot_words",
        "params": {}
    },
    {
        "name": "搜索欢迎页 (search/welcome_page/v2)",
        "path": "/bbs/app/api/search/welcome_page/v2",
        "params": {}
    },
    {
        "name": "话题分类目录 (topic/categories_v2)",
        "path": "/bbs/app/topic/categories_v2",
        "params": {}
    },
    {
        "name": "热点新闻列表 (hot_news/main_list)",
        "path": "/bbs/app/hot_news/main_list",
        "params": {"offset": "0", "limit": "5"}
    },
    {
        "name": "社区活动与榜单 (hashtag/ranking)",
        "path": "/bbs/app/hashtag/ranking",
        "params": {"offset": "0", "limit": "5"}
    },
    {
        "name": "用户动态列表 (profile/user/link/list)",
        "path": "/bbs/app/profile/user/link/list",
        "params": {"userid": "YOUR_HEYBOX_ID", "offset": "0", "limit": "5"}
    },
    {
        "name": "用户粉丝列表 (profile/follower/list)",
        "path": "/bbs/app/profile/follower/list",
        "params": {"userid": "YOUR_HEYBOX_ID", "offset": "0", "limit": "5"}
    }
]

results = []

try:
    print(f"[*] 2. Executing verification on {len(test_suite)} confirmed /bbs/app/ endpoints...")
    
    for i, target in enumerate(test_suite):
        path = target["path"]
        name = target["name"]
        
        # 1. Obtain signature
        sign_url = f"http://127.0.0.1:{PORT}/sign?path={urllib.parse.quote(path)}"
        req = urllib.request.urlopen(sign_url, timeout=10)
        quad = json.loads(req.read().decode("utf-8"))["data"]
        
        # 2. Assemble parameters
        params = dict(target["params"])
        params.update({
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
        })
        
        url = f"https://api.xiaoheihe.cn{path}?{urllib.parse.urlencode(params)}"
        http_req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Linux; Android 14; 25102RKBEC Build/UP1A.231005.007; wv) AppleWebKit/537.36",
                "Accept": "application/json",
                "Cookie": "pkey=YOUR_TEST_PKEY; heybox_id=76644009",
                "Referer": "https://api.xiaoheihe.cn",
                "Connection": "close"
            }
        )
        
        try:
            with urllib.request.urlopen(http_req, context=ctx, timeout=10) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                parsed = json.loads(body)
                api_status = parsed.get("status")
                api_msg = parsed.get("msg")
                has_data = ("result" in parsed and bool(parsed["result"])) or api_status == "ok"
                
                print(f"[{i+1}/{len(test_suite)}] {code} | {name:<26} ({path}): status={api_status!r} msg={api_msg!r} data={has_data}")
                results.append({
                    "name": name,
                    "path": path,
                    "code": code,
                    "status": api_status,
                    "msg": api_msg,
                    "data": has_data,
                    "preview": body[:120]
                })
        except urllib.error.HTTPError as e:
            print(f"[{i+1}/{len(test_suite)}] HTTP {e.code} | {name} ({path})")
            results.append({"name": name, "path": path, "code": e.code, "status": "HTTP_ERR", "data": False})
        except Exception as e:
            print(f"[{i+1}/{len(test_suite)}] ERR | {name}: {e}")
            results.append({"name": name, "path": path, "code": "ERR", "status": str(e), "data": False})
            
        time.sleep(1)

finally:
    proc.terminate()
    proc.wait()
    print("\n[*] 3. Signature microservice stopped cleanly.")

