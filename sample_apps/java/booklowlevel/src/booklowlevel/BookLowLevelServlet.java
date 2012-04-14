package booklowlevel;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.SimpleTimeZone;
import javax.servlet.http.*;
import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.KeyFactory;

@SuppressWarnings("serial")
public class BookLowLevelServlet extends HttpServlet {
    public void doGet(HttpServletRequest req,
                      HttpServletResponse resp)
        throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSSSSS");

        DatastoreService ds = DatastoreServiceFactory.getDatastoreService();

        Entity book = new Entity("Book");

        book.setProperty("title", "The Grapes of Wrath");
        book.setProperty("author", "John Steinbeck");
        book.setProperty("copyrightYear", 1939);
        Date authorBirthdate =
            new GregorianCalendar(1902, Calendar.FEBRUARY, 27).getTime();
        book.setProperty("authorBirthdate", authorBirthdate);

        ds.put(book);

        out.println("<p>Added a Book entity to the datastore via the low-level API, key: " +
                    KeyFactory.keyToString(book.getKey()) + "</p>");

        fmt.setTimeZone(new SimpleTimeZone(0, ""));
        out.println("<p>The time is: " + fmt.format(new Date()) + "</p>");
    }
}
