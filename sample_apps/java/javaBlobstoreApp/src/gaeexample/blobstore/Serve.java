package gaeexample.blobstore;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.api.blobstore.BlobKey;
import com.google.appengine.api.blobstore.BlobstoreService;
import com.google.appengine.api.blobstore.BlobstoreServiceFactory;

public class Serve extends HttpServlet {
    private BlobstoreService blobstoreService = BlobstoreServiceFactory.getBlobstoreService();

    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String key = req.getParameter("blob-key");
        if (key != null && !key.isEmpty()) {
            BlobKey blobKey = new BlobKey(key);

            blobstoreService.serve(blobKey, res);
        }

    }
}
