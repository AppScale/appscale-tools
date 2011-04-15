<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.util.List" %>
<%@ page import="javax.jdo.PersistenceManager" %>
<%@ page import="com.google.appengine.api.users.User" %>
<%@ page import="com.google.appengine.api.users.UserService" %>
<%@ page import="com.google.appengine.api.users.UserServiceFactory" %>
<%@ page import="guestbook.Greeting" %>
<%@ page import="guestbook.PMF" %>

<html>
  <head>
    <link type="text/css" rel="stylesheet" href="/stylesheets/main.css" />
  </head>

  <body>
<!--p>Your host: <%= request.getRemoteHost() %>.</p>
<p>url requested: <%= request.getRequestURI() %>.</p-->
<%
    UserService userService = UserServiceFactory.getUserService();
    User user = userService.getCurrentUser();
    if (user != null) {
%>
<p>Hello, <%= user.getNickname() 

%>!
</p><p></>You are <%if (!userService.isUserAdmin()){
	%>not<%
}
	%> admin!
 (You can
<a href="<%= userService.createLogoutURL(request.getRequestURI()) %>">sign out</a>.)</p>
<%
    } else {
%>
<p>Hello!
<a href="<%= userService.createLoginURL(request.getRequestURI()) %>">Sign in</a>
to include your name with greetings you post.</p>
<%
    }
%>



<%
    PersistenceManager pm = PMF.get().getPersistenceManager();
    String query = "select from " + Greeting.class.getName() + " order by date desc range 0,10";
 //   System.out.println("before execute query");
    long t1 = System.nanoTime();
    List<Greeting> greetings = (List<Greeting>) pm.newQuery(query).execute();
    long t2 = System.nanoTime();
    double queryTime =  (t2 - t1)/1000000.0;  
    if (greetings.isEmpty()) {
%>
<p>The guestbook has no messages.</p>
<%
    } else {
        for (Greeting g : greetings) {
            if (g.getAuthor() == null) {
%>
<p>An anonymous person wrote:</p>
<%
            } else {
%>
<p><b><%= g.getAuthor().getNickname() %></b> wrote:</p>
<%
            }
%>
<blockquote><%= g.getContent() %> -----------id of the post is: <%= g.getId() %></blockquote>
<%
        }
    }
%>
    <p><b>queryTime is <%= queryTime %></b></p>
<%  
    pm.close();
%>

    <form action="/sign" method="post">
      <div><textarea name="content" rows="3" cols="60"></textarea></div>
      <div><input type="submit" value="Post Greeting" /></div>
    </form>
	
	
	
	<form action="/deleteEntry" method="post">
		<div><input type="text" name="id" size=60 maxlength=200
<% 	if (request.getParameter("fail")==null){
%>	
	value="input the id of the post to delete"
<%
	}else{
%>
	value="id: <%=request.getParameter("fail")%> does not exist!" 
<%
	}
%>	
	/></div>
	<div>	
	<input type="submit" value="Delete Entry"/>
	</div>
	</form>
  </body>
</html>
