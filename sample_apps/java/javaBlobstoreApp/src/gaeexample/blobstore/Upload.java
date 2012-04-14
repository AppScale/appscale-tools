package gaeexample.blobstore;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.api.blobstore.BlobKey;
import com.google.appengine.api.blobstore.BlobstoreService;
import com.google.appengine.api.blobstore.BlobstoreServiceFactory;

public class Upload extends HttpServlet {

    private BlobstoreService blobstoreService = BlobstoreServiceFactory.getBlobstoreService();

    public void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

        Map<String, BlobKey> blobs = blobstoreService.getUploadedBlobs(req);
        BlobKey blobKey = blobs.get("myFile");
        BlobKeyCache bc = BlobKeyCache.getBlobKeyCache();

        if (blobKey == null)
            System.out.println("blobkey is null");
        else {
            bc.add(blobKey);
            res.sendRedirect("/serve.jsp?blob-key=" + blobKey.getKeyString() + "&fromUpdate=1");
        }
    }
}