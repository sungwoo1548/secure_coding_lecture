<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>
<body>
<% 	
	String cname = "";
	String sname = "";
	Cookie[] cs = request.getCookies();
	for (int i = 0; i < cs.length; i++) {
		if ("cname".equals(cs[i].getName())) {
			cname = cs[i].getValue();
		}
	}
	
	sname = (String)session.getAttribute("sname");
%>
<br>쿠키로부터 >>> <%=cname%> 또 안녕~
<br>세션으로부터 >>> <%=sname%> 또 안녕~
</body>
</html>
