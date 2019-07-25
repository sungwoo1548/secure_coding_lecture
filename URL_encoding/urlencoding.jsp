
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>
	<%
		String pcompany = request.getParameter("company");
		if (pcompany == null) {
			pcompany = "";
		}
		out.print("회사이름은 " + pcompany + "입니다.");
	%>
	<form>
		<input type="text" name="company" value=""/>
		<input type="submit"> 
	</form>

	<a href="?company=<%=pcompany%>">링크로 접근</a>
       <a href="?company=<%=java.net.URLEncoder.encode(pcompany, "UTF-8")%>">링크로 접근</a>
</body>
</html>
