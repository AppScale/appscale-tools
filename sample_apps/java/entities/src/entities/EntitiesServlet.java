package entities;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.SimpleTimeZone;
import javax.servlet.http.*;
import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;

@SuppressWarnings("serial")
public class EntitiesServlet extends HttpServlet {
    public void doGet(HttpServletRequest req,
                      HttpServletResponse resp)
        throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();

        DatastoreService ds = DatastoreServiceFactory.getDatastoreService();

        // Put a new entity with a system ID
        Entity e1 = new Entity("Kind");
        e1.setProperty("prop1", 1);
        ds.put(e1);
        out.println("<p>Created an entity with a system ID, key: " +
                    KeyFactory.keyToString(e1.getKey()) + "</p>");
        
        // Put a new entity with a key name
        Entity e2 = new Entity("Kind", "keyName");
        e2.setProperty("prop1", 2);
        ds.put(e2);
        out.println("<p>Created an entity with a key name, key: " +
                    KeyFactory.keyToString(e2.getKey()) + "</p>");

        // Batch put
        Entity e3 = new Entity("Kind");
        e3.setProperty("prop1", 3);
        Entity e4 = new Entity("Kind");
        e4.setProperty("prop1", 4);
        ds.put(new ArrayList(Arrays.asList(e3, e4)));

        try {
            // Get by key
            Entity result;
            result = ds.get(e1.getKey());
            out.println("<p>Retrieved an entity via key " +
                        KeyFactory.keyToString(e1.getKey()) + ", " +
                        "prop1 = " + result.getProperty("prop1") + "</p>");
            
            result = ds.get(e2.getKey());
            out.println("<p>Retrieved an entity via key " +
                        KeyFactory.keyToString(e2.getKey()) + ", " +
                        "prop1 = " + result.getProperty("prop1") + "</p>");

            // Batch get
            Map<Key, Entity> results =
                ds.get(new ArrayList(Arrays.asList(e3.getKey(), e3.getKey())));
            result = results.get(e3.getKey());
            out.println("<p>Retrieved an entity via key " +
                        KeyFactory.keyToString(e3.getKey()) + ", " +
                        "prop1 = " + result.getProperty("prop1") + "</p>");

        } catch (EntityNotFoundException e) {
            out.println("<p>Attempted to get an entity, but couldn't find it: " +
                        e + "</p>");
        }

        // Delete by key
        ds.delete(e1.getKey());
        ds.delete(e2.getKey());

        // Batch delete
        ds.delete(new ArrayList(Arrays.asList(e3.getKey(), e4.getKey())));

        out.println("<p>Deleted all entities.</p>");

        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSSSSS");
        fmt.setTimeZone(new SimpleTimeZone(0, ""));
        out.println("<p>The time is: " + fmt.format(new Date()) + "</p>");
    }
}
