package gaeexample.blobstore;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.api.blobstore.BlobKey;
import com.google.appengine.api.blobstore.BlobstoreService;
import com.google.appengine.api.blobstore.BlobstoreServiceFactory;

public class Delete extends HttpServlet {

    private BlobstoreService blobstoreService = BlobstoreServiceFactory.getBlobstoreService();

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        BlobKey key = new BlobKey(req.getParameter("blob-key"));
        blobstoreService.delete(key);
        BlobKeyCache bc = BlobKeyCache.getBlobKeyCache();
        bc.remove(key);
        resp.sendRedirect("/serve.jsp?blob-key=" + key.getKeyString() + "&fromUpdate=0");
    }
}
