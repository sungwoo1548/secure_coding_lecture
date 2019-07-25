
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>
	<%
		String phtml = request.getParameter("html");
		if (phtml == null) {
			phtml = "";
		}

        phtml.replaceAll("<","&lt");
        phtml.replaceAll(">","&gt");

		out.print("입력한 내용은 " + phtml + "입니다.");
	%>
	<form>
		<input type="text" name="html" value=""/>
		<input type="submit"> 
	</form>
</body>
</html>
