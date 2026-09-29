package com.xiaoheihe;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class XiaoHeiHeClient {

    public static void main(String[] args) {
        try {
            System.out.println("[*] Step 1: Bootstrapping Unidbg Engine...");
            XiaoHeiHeSignerRunner runner = new XiaoHeiHeSignerRunner();

            // Target endpoint
            String path = "/bbs/app/feeds/news";
            long now = System.currentTimeMillis() / 1000;

            System.out.println("[*] Step 2: Generating 100% Genuine Native Signature Quadruple...");
            XiaoHeiHeSignerRunner.SignResult sig = runner.sign(path, now);

            System.out.println("\n[+] Native Quadruple Generated:");
            System.out.println("  _time : " + sig._time);
            System.out.println("  nonce : " + sig.nonce);
            System.out.println("  hkey  : " + sig.hkey);
            System.out.println("  _rnd  : " + sig._rnd);

            System.out.println("\n[*] Step 3: Assembling complete request with offset=0 & limit=20...");
            Map<String, String> params = new LinkedHashMap<>();
            // Business Parameters
            params.put("offset", "0");
            params.put("limit", "20");
            // Security Protocol Parameters
            params.put("heybox_id", "10000001");
            params.put("imei", "0000000000000000");
            params.put("device_info", "25102RKBEC");
            params.put("os_type", "Android");
            params.put("x_os_type", "Android");
            params.put("x_client_type", "mobile");
            params.put("os_version", "14");
            params.put("version", "1.3.385");
            params.put("build", "385");
            params.put("channel", "heybox_xiaomi");
            params.put("x_app", "heybox");
            params.put("time_zone", "Asia/Shanghai");
            params.put("dw", "2");
            params.put("netmode", "wifi");
            params.put("_time", sig._time);
            params.put("nonce", sig.nonce);
            params.put("hkey", sig.hkey);
            params.put("_rnd", sig._rnd);

            String query = params.entrySet().stream()
                    .map(e -> {
                        try {
                            return URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8.name()) + "=" +
                                   URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8.name());
                        } catch (Exception ex) {
                            return e.getKey() + "=" + e.getValue();
                        }
                    })
                    .collect(Collectors.joining("&"));

            String urlStr = "https://api.xiaoheihe.cn" + path + "?" + query;
            System.out.println("[*] Request URL: " + urlStr);

            URI uri = URI.create(urlStr);
            URL url = uri.toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14; 25102RKBEC Build/UP1A.231005.007; wv) AppleWebKit/537.36");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Cookie", "pkey=YOUR_SAMPLE_PKEY_TOKEN; heybox_id=10000001");
            conn.setRequestProperty("Referer", "https://api.xiaoheihe.cn");
            conn.setRequestProperty("Connection", "close");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            int code = conn.getResponseCode();
            System.out.println("\n[+] HTTP Response Status: " + code);

            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    code >= 200 && code < 400 ? conn.getInputStream() : conn.getErrorStream(),
                    StandardCharsets.UTF_8
            ));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            reader.close();

            String body = sb.toString();
            System.out.println("[+] Response Body Preview:\n" + (body.length() > 800 ? body.substring(0, 800) + "..." : body));

            if (body.contains("\"status\":\"ok\"") || body.contains("\"links\"") || body.contains("\"feed_list\"")) {
                System.out.println("\n=======================================================================");
                System.out.println("  >>> MISSION ACCOMPLISHED: 100% GENUINE API DATA FETCHED! <<<");
                System.out.println("=======================================================================\n");
            }
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}

