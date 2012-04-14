<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.util.List" %>
<%@ page import="javax.jdo.PersistenceManager" %>
<%@ page import="com.google.appengine.api.users.User" %>
<%@ page import="com.google.appengine.api.users.UserService" %>
<%@ page import="com.google.appengine.api.users.UserServiceFactory" %>
<%@ page import="guestbook_memcached.Greeting" %>
<%@ page import="guestbook_memcached.PMF" %>
<%@ page import="net.sf.jsr107cache.CacheManager" %>
<%@ page import="net.sf.jsr107cache.CacheFactory" %>
<%@ page import="net.sf.jsr107cache.CacheException" %>
<%@ page import="net.sf.jsr107cache.Cache" %>
<%@ page import="net.sf.jsr107cache.CacheStatistics" %>

<%@ page import="java.util.Collections" %>
<%@ page import="com.google.appengine.api.memcache.jsr107cache.GCacheFactory" %>


<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Map" %>


<html>
  <head>
    <link type="text/css" rel="stylesheet" href="/stylesheets/main.css" />
  </head>

  <body>
<%
	Cache cache = null;

		Map props = new HashMap();
        props.put(GCacheFactory.EXPIRATION_DELTA, 15);
        try {
            CacheFactory cacheFactory = CacheManager.getInstance().getCacheFactory();
            cache = cacheFactory.createCache(props);
        } catch (CacheException e) {

        }
        
    UserService userService = UserServiceFactory.getUserService();
    User user = userService.getCurrentUser();
    if (user != null) {
%>
<p>How are you!, <%= user.getNickname()

%>!
</p><p></>Hi! You are <%if (!userService.isUserAdmin()){
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
	double queryTime = 0;
	PersistenceManager pm = null;
	long t1 = System.nanoTime();
	List<Greeting> greetings = (List<Greeting>)cache.get("greetings");
	long t2 = System.nanoTime();
	if (greetings == null){
    	pm = PMF.get().getPersistenceManager();
    	String query = "select from " + Greeting.class.getName() + " order by date desc range 0,10";
    	t1 = System.nanoTime();
    	List<Greeting> greetingsTemp = (List<Greeting>) pm.newQuery(query).execute();
    	t2 = System.nanoTime();
    	greetings = new ArrayList<Greeting>();
    	greetings.addAll(greetingsTemp);
    	
    	cache.put("greetings", greetings);
    }
    queryTime =  (t2 - t1)/1000000.0;
  
  	CacheStatistics stats = cache.getCacheStatistics();
  	int hits = stats.getCacheHits();
    int misses = stats.getCacheMisses();
    int objCount = stats.getObjectCount();
    
    if (greetings.isEmpty()) {
%>
<p>The guestbook has no messages.</p>
<%
    } else {
        for (Greeting g : greetings) {
            if (g.getAuthor() == null) {
%>
<p>An anonymous person wrote---:</p>
<%
            } else {
%>
<p><b><%= g.getAuthor().getNickname() %></b> wrote---:</p>
<%
            }
%>
<blockquote><%= g.getContent() %> -----------id of the post is: <%= g.getId() %></blockquote>
<%
        }
    }
%>
    <p><b>queryTime is <%= queryTime %></b></p>
    <p><b>hits is <%= hits %></b></p>
    <p><b>misses is <%= misses %></b></p>
    <p><b>ObjectCount is <%= objCount %></b></p>
<%
	if (pm != null)
	    pm.close();
%>
    <form action="/sign" method="post">
      <div><textarea name="content" rows="3" cols="60"></textarea></div>
      <div><input type="submit" value="Post Greeting" /></div>
    </form>



<form action="/deleteEntry" method="post">
                <div><input type="text" name="id" size=60 maxlength=200
<%      if (request.getParameter("fail")==null){
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
