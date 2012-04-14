<%@ page import="com.google.appengine.api.blobstore.BlobstoreServiceFactory" %>
<%@ page import="com.google.appengine.api.blobstore.BlobstoreService" %>

<%
    BlobstoreService blobstoreService = BlobstoreServiceFactory.getBlobstoreService();
%>


<html>
    <head>
        <title>Upload Test</title>
    </head>
    <body>
    	<p>After you submit a file, the file is automatically downloaded</p>
    	<p>to re-submit a file, please hit "refresh" button</p>
        <form action="<%= blobstoreService.createUploadUrl("/upload") %>" method="post" enctype="multipart/form-data">
            <input type="text" name="foo">
            <input type="file" name="myFile">
            <input type="text" name="description">
            <input type="submit" value="Submit">
        </form>
        
        <form action="/" method="get">
            <input type="submit" value="refresh">
        </form>
        
    </body>
</html>