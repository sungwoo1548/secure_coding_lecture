<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>
<body>
<% 	// 스크립틀릿 : JSP에서 동적 처리하는 부분을 기술
	
	// 요청 파라미터 목록으로부터 이름이 name인 파라미터의 값을 문자열로 반환 
	String pname = request.getParameter("name");
	if (pname == null || pname.equals("")) {
%>
		<form action="hello.jsp" method="post">
			<input type="text" name="name" value="">
			<input type="submit" value="안녕">
		</form>		
<%		
	} else {
		// 파라미터로 전달된 값을 쿠키에 저장 및 화면 출력
		Cookie c = new Cookie("cname", pname);
		c.setDomain("localhost");
		c.setPath("/openeg");
		c.setMaxAge(60*60*24);
		response.addCookie(c);
		
		// 세션에 저장
		session.setAttribute("sname", pname);
		
		out.print(pname + " 안녕!!!");		
	}
%>	

<a href="hello2.jsp">또 안녕</a>

</body>
</html>
