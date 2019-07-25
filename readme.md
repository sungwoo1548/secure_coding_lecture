# 20190722) start 

books)
1. 그림 설명으로 한번에 이해할 수 있는 보안의 기본 - 위즈플래닛
2. 해킹 방어를 위한 JAVA 시큐어코딩 - 오픈이지북스
-----------------------------------------------------------

* SQL injection
외부 입력값을 쿼리 조작 문자열 포함 여부를 검증하지 않고 쿼리 작성 및 실행에 사용하는 경우, 쿼리의 구조와 의미가 변경되서 실행되는 것
    - 데이터베이스에 대해 침해 -> 권한 밖의 데이터를 조회, 수정, 삭제, 생성 가능
    - 서버에 대한 공격 -> 데이터베이스가 동작하는 서버의 제어권을 획득해서 원격지에서 해당 서버를 제어

*XSS 공격 (Cross-Site Scripting or Corss-Site Script)
크로스사이트 스크립트(팅)
공격자가 전달한 스크립트 코드가 사용자 브라우져를 통해서 실행되는 것 (=동적페이지가 생성될 때)
    - 브라우저에 저장된 또는 PC에 저장된 정보를 탈취
    - 가짜 페이지를 만들고 사용자로 하여금 입력을 유도해서 입력값을 탈취
    - 해당 pc의 제어권을 탈취해서 원격에서 제어 -> 좀비화 -> BeEF 프레임웍 이용


    --------------------------------------------------------

* 입력값 검증)
입력값의 정상 여부를 확인하는 과정


예) ID 중복 체크 로직을 구현
1. 입력화면
ID: 123 or 1=1 [체크]

2. 사용자 입력을 요청 파라미터로 서버로 전달
http://.../check.jsp?id=123 or 1=1

3. 요청 파라미터로 전달된 값은 서버 내부 처리를 위해서 사용
select * from users where id = 123 or 1=1


SQL 삽입(Injection), 운영체제 명령어 삽입(Command Injection), 신뢰되지 않은 URL 주소로 자동 접속 연결(Open Redirect)


-----------------------------------------------------------------
인증 (Authentification)
    1) 지식 기반 ( id, pw)
    2) 소유 기반 ( 하드웨어, 카드, usb 등)
    3) 바이오 기반 (지문, 눈, 목소리, 정맥 등)
    4) 다중요소 기반 (1~3 혼합)

인가 ( = 권한, = 접근통제) (Authorization)
    1) 화면상의 인가
    2) 기능상의 인가
    3) 데이터 상의 인가



------------------------------------------------------------
* 개발보안...
* 정보보호 사전점검.... ( 개발중 >> 민간 확대 3년이내?)
    - 자격 진단원...
* 운영/유지 ISMS








# 20190723

* 용어
    - DLP : 데이터 유출 방지 (Data Loss Prevention)
    - DRP : 디지털 권리 관리 (Digital Rights Management)
    
    - SDL : 보안개발프로세스 (Secure Development Lifecycle)

* 파일 업로드의 잘 못된 구현
    1) 파일 크기 종류 제한 x
        크기 문제)
        - 서버 스토리지(디스크) 자원 고갈
        - 서버 연결 자원 고갈
            => 정상 서비스 방해 = Dos 공격
        종류 문제)
        - 서버에서 실행되는 파일 업로드 (SSS 서버사이드스크립트 PHP,ASP,JSP...등)
            => 서버 제어권 탈취
        - 클라이언트에서 실행되는 파일 업로드
            => 악성코드 유포지로 활용될 수 있음
    
    2) 외부 접근가능 한 경로에 저장됨

* 패스워드
    1) 생성 / 변경 규칙
        - 복잡도 : 영문(26), 숫자(10), 특수문자(13) - 8자리 이상 / 2가지 조합은 10자리 이상. 
        - 사전에 등록된 문자열 사용x
        - 규칙성 x
        - 개인정보 연관x
    2) 저장(보관) 규칙
        - 암호화 후 보관 : 해시함수(단방향 유일 함수) 
    3) 관리 정책
        - 변경주기
        - 최근 사용 패스워드 히스토리 관리
        - 최소 사용기간 

## Secure coding 필요성 숙지.
### 취약점 DB 확인
    - CWE : 보안 약점 (Common Weakness Enumeration) / 문제의 원인의 가능성이 있음..
    - CVE : 보안 취약점 (Common Vulnerabilities and Exposures) / 문제로 나타난 것들..
    - SANS TOP 25 
    - OWASP TOP 10 
### Secure coding 가이드
    - CERT
    - 개발보안가이드
### 방법론
    - MS-SDL
    - 7 touch point
    - CLASP


## 주요 취약점
### SQL injection 방어
#### URL 또는 SQL에 사용되는 의미를 가진 특수 문자를 처리해야함.
    SQL : ', #, ;, -
    URL : ?, &, =
    1) 이스케이프 문자를 사용하여 처리
    2) 입력값 검증

### CSRF(크로스사이트 요청위조)
    서버로 전달된 요청을 요청 절차와 주체에 대한 검증을 수행하지 않고 요청을 처리했을 때 발생

### BoF (Buffuer over Flow)
### 경로 조작, 경로 추적
    특정 디렉터리에 존재하는 파일을 내려주는 서비스 ⇒ 파일 다운로드
    .../download.jsp?filename=abc.gif
    ~~~~~~~~~~~~
    new File("/data/upload/" + filename);
    .../download.jsp?filename=../../../../../../etc/passwd ⇐ 경로조작 → 접근할 수 없는 디렉터리와 파일에 접근이 가능


# 20190724
## 실습
### injection
    1) id에 `admin'#` >>  server에서 `where id = 'admin'#' pw = 'xxx'`
                        뒤 구문이 주석처리됨.
    
### DVWA
    취약점을 모아놓은 패키지
    (Welcome to Damn Vulnerable Web App)

### 프록시사용
    paros)
        요청 catch : trap 
    burp suite)
        요청 catch : intercept

## HTTP와 웹 구조 2번책 131페이지

## HTTP 구조적 특징
    1) Stateless = 커넥션리스, 연결유지x
    2) 요청/응답 구조
        -> 알파넷 시절, 정적문서 요청에 대한 프로토콜이 HTTP
        다수의 연결을 유지하면 이용제한이 걸림...
        요청에 대한 정적 문서 전달 후 연결 종료.

## 동적 페이지의 등장
    1) 동적 처리를 위한 어플리케이션 서버... PHP, JSP, ASP 등
    2) 하드웨어의 발달로 처리기능 향상됨
        - 비즈니스 처리 Servlet
    3) 가상화기술.. 컨테이너... docker 등장
    4) 모듈화 프레임웍... Micro Service Architecture.

# 20190725
## 인증과 인가
### 인증 (Authentication)
    인증은, 서버의 자원을 사용하려는 주체의 신원을 식별(Identification)하는 작업.

    인증방식
    Type1 : 지식기반 ; 패스워드, 보안질문, PIN ... 등
    Type2 : 소유기반 ; 메모리카드, 스마트카드, USB ... 등
    Type3 : 바이오기반 ; 지문, 음성, 정맥, 홍채, 서명 ... 등

    두가지 복합 = 2 factor 인증
    두가지 이상 = multi factor 인증 = 다중 인증

### 인가 (Authorization)
    자원접근 권한을 확인 = 접근통제 

    접근통제 기술
    접근제어목록(ACL:Access Control List) 
    https://ko.wikipedia.org/wiki/%EC%A0%91%EA%B7%BC_%EC%A0%9C%EC%96%B4_%EB%AA%A9%EB%A1%9D
        : 사용자 또는 자원 중심의 접근통제 목록을 작성하여 접근 제어시 목록을 비교하여 접근통제.
    접근통제표(ACM:Access Control Matrix) 
        : 자원 중심의 접근통제 표를 작성하여 접근 제어시 표와 비교하여 접근 통제.
    강제적 접근통제(MAC:Mandotory Access Control)
        : 사용자와 자원에 적절한 보안등급(레이블)을 부여하여 접근 제어시 등급을 비교하여 접근 통제
    역할기반 접근통제(RBAC:Role Base Access Control)
        : 사용자에게 역할(Role)을 부여하고 각 역할별로 권한을 부여 접근 통제

### 웹 인증 방식
    세션사용 여부로 나뉨
    1) 세션을 사용하지 않는 HTTP 인증
    : 요청시마다 인증정보를 가지고 가야함 = 노출빈도 높음 = 유출 가능성 높음
        -Bassic Authentication https://flylib.com/books/en/1.2.1.125/1/
        -HTTP Digest Authentication
        -HTTP NTLM Authentication
        -Anonymous Authentication
    
    2) 세션을 사용하는 인증
        -Form Based Authentication

## 보안취약접 제거를 위한 코딩 기법 p189
### 입력값에 대한 확인 절차가 생략되는 경우 다양한 인젝션(삽입) 취약점이 발생할 수 있다.
    - DB 데이터를 조작하는 SQL문에 검증되지 않은 외부 입력값을 사용하는 경우
    - 내부에서 실행되는 명령어나 명령어의 인자(argument)로 검증되지 않은 외부 입력값 사용
    - LDAP 조회를 위한 필터 조립에 검증되지 않은 외부 입력값사용
    - Xpath 쿼리 작성에 검증되지 않은 외부 입력값 사용
    - XQuery 쿼리 작성에 검증되지 않은 외부 입력값 사용
    - SOAP 서비스 요청 메시지 작성에 검증되지 않은 외부 입력값 사용

### 검증 절차
    - 규범화 (Canonicalization)
        : 데이터 손실 없이 입력 데이터를 가장 간단하면서 대등한 형태로 축소하는 과정
    - 정규화 (Normalization)
        : 데이터 손실은 있지만 알려진 가장 간단한 형태로 변환하는 과정
    - 새니타이즈 (Sanitization)
        : 데이터를 받은 서브시스템의 요구사항에 맞게 데이터를 가공하는 과정
    - 검증 (Validation)
        : 입력 데이터가 프로그램의 정당한 프로그램 입력 영역 안에 있는지 확인하는 과정

### 취약점 1) SQL 삽입
    가능한 피해 :
    - DB 정보 열람 및 추가, 수정 삭제
    - 프로시저를 통해 운영체제 명령어 수행
    - 웹 애플리케이션을 조정해 다른 시스템 공격
    - 외부 프로그램 사용
    - 불법 로그인

예시) search.jsp

`String ptext = request.getParameter("text");`

`String query = "select * from data where keyword = '" + ptext + "'";`

`Statement stmt = connection.createStatement();`

`stmt.executeQuery(query);`

    case1) 항상 참이 되는 입력 => 모든 내용이 반환됨 = 권한 밖의 데이터에 대해 접근이 가능함

    정상적인 요청 : search.jsp?text=abcd
        query = select * from data where keyword = 'abcd'
    비정상적인 요청 : search.jsp?text=abcd' or 'a'='a
        quety = select * fromd ata where keyword = 'abcd' or 'a' = 'a'


    case2) 오류를 유발하는 입력
    search.jsp?text=abcd'
        query = select * from data where keyword = 'abcd''
    => 홑따움표의 개수가 일치하지 않아서 오류가 발생 = 오류 메시지에 대한 처리가 불완전하여 시스템 내부 정보가 사용자 화면에 출력될 수 있음

    