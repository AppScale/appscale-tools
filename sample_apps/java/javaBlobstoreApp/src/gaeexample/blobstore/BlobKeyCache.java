package gaeexample.blobstore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.sf.jsr107cache.Cache;
import net.sf.jsr107cache.CacheException;
import net.sf.jsr107cache.CacheManager;

import com.google.appengine.api.blobstore.BlobKey;

public class BlobKeyCache {
    private static BlobKeyCache bc = null;
    private Cache cache;

    public BlobKeyCache() {
        if (cache == null) {
            try {
                cache = CacheManager.getInstance().getCacheFactory().createCache(Collections.emptyMap());
            } catch (CacheException e) {
                e.printStackTrace();
            }
        }
    }

    public static BlobKeyCache getBlobKeyCache() {
        if (bc == null) {
            bc = new BlobKeyCache();
        }
        return bc;
    }

    @SuppressWarnings("unchecked")
    public void add(BlobKey key) {
        ArrayList<BlobKey> blobList = (ArrayList<BlobKey>) cache.get("blobs");
        if (blobList == null)
            blobList = new ArrayList<BlobKey>();
        blobList.add(key);
        blobList.remove("blobs");
        cache.put("blobs", blobList);
    }

    @SuppressWarnings("unchecked")
    public void remove(BlobKey bk) {
        ArrayList<BlobKey> blobList = (ArrayList<BlobKey>) cache.get("blobs");
        if (blobList != null && blobList.contains(bk))
            blobList.remove(bk);
        cache.put("blobs", blobList);
    }

    public List<BlobKey> getCache() {
        ArrayList<BlobKey> blobList = (ArrayList) cache.get("blobs");
        if (blobList == null)
            blobList = new ArrayList<BlobKey>();
        return blobList;
    }
}
