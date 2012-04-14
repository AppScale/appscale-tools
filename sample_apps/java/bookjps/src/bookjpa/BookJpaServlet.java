package bookjpa;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.SimpleTimeZone;
import javax.persistence.EntityManager;
import javax.servlet.http.*;
import com.google.appengine.api.datastore.KeyFactory;

import bookjpa.EMF;
import bookjpa.Book;

@SuppressWarnings("serial")
public class BookJpaServlet extends HttpServlet {
    public void doGet(HttpServletRequest req,
                      HttpServletResponse resp)
        throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();

        EntityManager em = EMF.get().createEntityManager();
        Book book = new Book();
        book.setTitle("The Grapes of Wrath");
        book.setAuthor("John Steinbeck");
        book.setCopyrightYear(1939);
        Date authorBirthdate =
            new GregorianCalendar(1902, Calendar.FEBRUARY, 27).getTime();
        book.setAuthorBirthdate(authorBirthdate);
        try {
            em.persist(book);
        } finally {
            em.close();
        }

        // Because we're asking for a system-assigned ID in the key,
        // we can't access the Book's key until after the
        // EntityManager has closed and the Book has been saved.  For
        // this example, we allow an exception thrown by the datastore
        // to propagate to the runtime environment and assume that if
        // we got here the Book was saved properly.
        out.println("<p>Added a Book entity to the datastore via JPA, key: " +
                    KeyFactory.keyToString(book.getKey()));

        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSSSSS");
        fmt.setTimeZone(new SimpleTimeZone(0, ""));
        out.println("<p>The time is: " + fmt.format(new Date()) + "</p>");
    }
}
