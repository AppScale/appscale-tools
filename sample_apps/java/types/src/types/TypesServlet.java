package types;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.SimpleTimeZone;
import javax.servlet.http.*;
import com.google.appengine.api.datastore.Blob;
import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.GeoPt;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.ShortBlob;
import com.google.appengine.api.datastore.Text;

@SuppressWarnings({ "serial", "unchecked" })
public class TypesServlet extends HttpServlet {
    public void doGet(HttpServletRequest req,
                      HttpServletResponse resp)
        throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();

        DatastoreService ds = DatastoreServiceFactory.getDatastoreService();

        Entity e1 = new Entity("Kind");

        e1.setProperty("stringProp", "string value, limited to 500 bytes");

        Text textValue = new Text("text value, can be up to 1 megabyte");
        e1.setProperty("textProp", textValue);

        byte[] someBytes = { 107, 116, 104, 120, 98, 121, 101 };
        ShortBlob shortBlobValue = new ShortBlob(someBytes);
        e1.setProperty("shortBlobProp", shortBlobValue);

        Blob blobValue = new Blob(someBytes);
        e1.setProperty("blobProp", blobValue);

        e1.setProperty("booleanProp", true);

        // returned as a long by the datastore
        e1.setProperty("integerProp", 99);

        e1.setProperty("floatProp", 3.14159);

        e1.setProperty("dateProp", new Date());

        e1.setProperty("nullProp", null);

        GeoPt geoPtValue = new GeoPt(47.620339f, -122.349629f);
        e1.setProperty("geoptProp", geoPtValue);

        ArrayList<Object> mvp = new ArrayList<Object>();
        mvp.add("string value");
        mvp.add(true);
        mvp.add(3.14159);
        e1.setProperty("multivaluedProp", mvp);

        ds.put(e1);
        out.println("<p>Created an entity, key: " +
                    KeyFactory.keyToString(e1.getKey()) + "</p>");

        Entity e2 = new Entity("Kind");
        e2.setProperty("keyProp", e1.getKey());
        ds.put(e2);

        out.println("<p>Created an entity, key: " +
                    KeyFactory.keyToString(e2.getKey()) + "</p>");

        try {
            Entity result = ds.get(e1.getKey());

            // All integer types returned as Long.
            Long resultIntegerPropValue =
                (Long) result.getProperty("integerProp");

            if (resultIntegerPropValue == null) {
                out.println("<p>Entity didn't have a property named integerProp.</p>");
            } else {
                out.println("<p>Entity property integerProp = " +
                            resultIntegerPropValue + "</p>");
            }

            // Multivalued properties returned as List.
            List<Object> resultMvp =
                (List<Object>) result.getProperty("multivaluedProp");
            if (resultMvp == null) {
                out.println("<p>Entity didn't have a property named multivaluedProp.</p>");
            } else {
                out.println("<p>Multivalued property values:</p><ul>");
                for (Object v : resultMvp) {
                    out.println("<li>" + v + "</li>");
                }
                out.println("</ul>");
            }

        } catch (EntityNotFoundException e) {
            out.println("<p>Attempted to get an entity, but couldn't find it: " +
                        e + "</p>");
        }

        ds.delete(e1.getKey());
        ds.delete(e2.getKey());
        out.println("<p>Entities deleted.</p>");

        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSSSSS");
        fmt.setTimeZone(new SimpleTimeZone(0, ""));
        out.println("<p>The time is: " + fmt.format(new Date()) + "</p>");
    }
}
