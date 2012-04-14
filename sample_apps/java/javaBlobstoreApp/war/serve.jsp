<%@ page import="gaeexample.blobstore.BlobKeyCache" %>
<%@ page import="java.util.List" %>
<%@ page import="com.google.appengine.api.blobstore.BlobKey;" %>

<%
    BlobKeyCache bc = BlobKeyCache.getBlobKeyCache();
    List<BlobKey> keys = bc.getCache();
%>

<html>
    <head>
        <title>Upload Test</title>
    </head>
    <body>
    	<% 
    		String fromUpdate = request.getParameter("fromUpdate");
    		if (fromUpdate.equals("1")) {
    	%>
    		<p>The Blob you just upload is</p>
    	<% 
    		} 
    		else {
    	%>
    	    <p>The Blob you just delete is</p>
    	<%  
    		}
    	%>
    	<p><%= "blob-key: "+ request.getParameter("blob-key")%></p>
    	<p>A List of Uploaded Blobs</p>
    	<% 
    	   for (BlobKey key : keys) {
    	 %>
           <ul><%= "key: "+ key.getKeyString() %></ul>
         <% 
           }
         %>
         <p>You can download the blob by putting the blob keys</p>
         <form action="/serve" method="post">
            <input type="text" name="blob-key">
            <input type="submit" value="Submit">
         </form>
         <p>You can delete a blob</p>
         <form action="/delete" method="post">
            <input type="text" name="blob-key">
            <input type="submit" value="Submit">
         </form>
    </body>
</html>