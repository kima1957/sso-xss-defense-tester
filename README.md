# XSS Defense Tester (SSO 8.1 / hub / LGTSSO)

SSO 8.1의 XSS 방어(`XssInterceptor` + 신규 `HubSecurityInterceptor`(`/hub`) +
신규 `XssBlockFilter`(`/LGTSSO`) + 출력 인코딩 + `returnURL` 검증)를 검증하는
**독립 실행형 HTTP 호출기**. JDK 1.8, 외부 의존성 없음(`HttpURLConnection`).

판정 철학은 `U-Plus_XSS_vulnerability_response.md` 문서 4.4 / 9절과 동일하다. 합격 기준은
"Interceptor/Filter가 차단했는가"가 아니라 **"위험 구문이 응답에서 실행 가능한 위치로
튀어나왔는가(breakout)"** 이다. 차단으로 통과하든 출력 인코딩으로 무해화돼 통과하든
둘 다 안전(PASS)으로 본다.

## ⚠ 사용 전 반드시

- **본인 소유의 로컬/테스트 서버**에 대해서만 실행할 것. 운영 서버 금지.
- payload 안의 attacker 호스트로는 **실제 요청을 보내지 않는다**(응답 구조만으로 판정하므로 자기완결적).
- 세션 쿠키 등 민감 값은 **코드에 넣지 말고** 환경변수로 주입.

## 테스트 대상 (요청 기준)

| 케이스 | 경로 | 파라미터 | 확인할 내용 | 적용 방어 |
| --- | --- | --- | --- | --- |
| Case1 | `/sso/ssoService.do` | `returnURL` | HTML attribute 또는 JavaScript 컨텍스트 반사 | `XssInterceptor`(`*.do`) |
| Case2 | `/LGTSSO/portlets/smartworkPortlet.jsp` | `tp` | JavaScript 컨텍스트 반사 | `XssBlockFilter`(`/LGTSSO/**`) |
| Case3 | `/LGTSSO/portlets/salesPortlet.jsp` | `tp` | HTML attribute 또는 이벤트 핸들러 컨텍스트 반사 | `XssBlockFilter`(`/LGTSSO/**`) |
| Case4 | `/hub/hub.do` | `returnURL` | JavaScript 컨텍스트 반사 | `XssInterceptor` + `HubSecurityInterceptor`(`/hub/**`) |

각 케이스마다 문서에서 요구한 컨텍스트 payload 외에, 블랙리스트 우회 확인용 추가 payload
(대소문자 변형, 개행 삽입, 단어목록에 없는 함수 사용 등)를 포함했다. `XssDefenseTester.java`의
`buildCases()`에서 케이스 ID로 그룹을 구분한다(`C1-*`, `C2-*`, `C3-*`, `C4-*`).

## 로컬 실행 (Windows PowerShell)

Java 8이 이미 설치되어 있다면 바로 실행 가능하다.

```powershell
cd D:\project\claude\xss-defense-tester

# 1) 컴파일 (한글 주석 때문에 -encoding UTF-8 필수)
javac -encoding UTF-8 XssDefenseTester.java

# 2) 대상 서버/등록 호스트 지정 (본인 로컬 서버 값으로 교체)
$env:SSO_BASE_URL    = "http://localhost:8080"   # 로컬에서 띄운 SSO/hub/LGTSSO 서버 주소
$env:SSO_REG_HOST    = "localhost"                # 실제 등록된 SSO 사이트 host
$env:SSO_UNREG_HOST  = "unregistered.example"     # 미등록 host (그대로 사용 가능)
$env:SSO_ATTACKER_HOST = "attacker.example"       # 판정용 문자열, 실제 호출 안 됨
# 인증이 필요한 엔드포인트면 세션 쿠키도 지정
# $env:SSO_COOKIE = "JSESSIONID=...."

# 3) 실행
java -Dfile.encoding=UTF-8 XssDefenseTester
```

또는 CLI 인자로 baseUrl / regHost 만 빠르게 지정:

```powershell
java -Dfile.encoding=UTF-8 XssDefenseTester http://localhost:8080 localhost
```

실행하면 콘솔에 **각 케이스가 실제로 호출한 전체 URL**이 그대로 출력되고
(`URL   : http://localhost:8080/sso/ssoService.do?returnURL=%22...`),
동일한 내용이 `logs\xss-test_<타임스탬프>.log` 파일에도 남는다. 실행 마지막 줄에
로그 파일의 전체 경로가 출력된다.

FAIL 또는 ERROR가 하나라도 있으면 종료코드 1 (스크립트에서 게이트로 사용 가능).

## 판정 결과

- **PASS**: 차단됐거나 안전 인코딩됨(breakout 없음)
- **FAIL**: 위험 구문이 실행 가능한 위치로 반사됨 / 정상 값 과차단
- **REVIEW**: JS 문자열이 escape된 것으로 보이나 실제 실행 여부는 브라우저 개발자도구로 확인 필요
- **ERROR**: 요청 실패(도달 불가, 타임아웃 등)

`[interceptor/filter fired]` 태그로 "차단으로 통과"인지 "인코딩으로 통과"인지 구분된다.

## 결과를 보고 추가로 확인할 것

1. **REVIEW로 나온 JS_STRING 케이스**: 스크립트만으로는 실제 브라우저 실행 여부를 100% 보장할
   수 없다. 로그에 찍힌 URL을 브라우저에 직접 붙여넣고, 개발자도구 Console/Network 탭에서
   `alert`, `fetch` 호출 흔적이 없는지 눈으로 확인한다(문서 7.3 기준).
2. **차단 신호(`blockRedirectMarkers`/`blockJsonMarkers`) 튜닝**: `HubSecurityInterceptor`,
   `XssBlockFilter`가 실제로 어떤 응답(리다이렉트 경로, 상태코드, JSON 바디)을 주는지 한 번
   확인한 뒤 `Config` 블록의 마커 목록을 실제 값에 맞게 조정하면 판정 정확도가 올라간다.
   (현재는 400/403 상태코드, `/error`, `xss`, `blocked` 등 포괄적 키워드로 추정 판정한다.)
3. **커스텀 소스 추가 케이스**: `/LGTSSO`는 고객사 커스텀 소스가 많다고 하셨으므로,
   `tp` 외에 다른 반사 파라미터가 있다면 `buildCases()`에 같은 패턴으로 케이스를 추가한다.

## 확장 아이디어

- 이중 인코딩 우회(`%253Cscript%253E`) 케이스 추가 — 문서의 반복 URL decode 대응 검증
- 앱의 실제 차단 응답 형태에 맞춰 `blockRedirectMarkers` / `blockJsonMarkers` 조정
- REVIEW(JS 실행) 케이스용 Playwright/Selenium 헤드리스 브라우저 검증 스텝 추가
