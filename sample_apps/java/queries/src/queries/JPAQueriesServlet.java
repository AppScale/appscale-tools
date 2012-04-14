package queries;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.SimpleTimeZone;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Query;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@SuppressWarnings("serial")
public class JPAQueriesServlet extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();

        EntityManagerFactory emf = EMF.get();
        EntityManager em = null;

        try {
            em = emf.createEntityManager();
            Book book = new Book("978-0141185064");
            book.setTitle("The Grapes of Wrath");
            book.setAuthor("John Steinbeck");
            book.setCopyrightYear(1939);
            Date authorBirthdate = new GregorianCalendar(1902, Calendar.FEBRUARY, 27).getTime();
            book.setAuthorBirthdate(authorBirthdate);

            em.persist(book);
        } finally {
            em.close();
        }

        try {
            em = emf.createEntityManager();
            Book book = new Book("978-0141185101");
            book.setTitle("Of Mice and Men");
            book.setAuthor("John Steinbeck");
            book.setCopyrightYear(1937);
            Date authorBirthdate = new GregorianCalendar(1902, Calendar.FEBRUARY, 27).getTime();
            book.setAuthorBirthdate(authorBirthdate);

            em.persist(book);
        } finally {
            em.close();
        }

        try {
            em = emf.createEntityManager();
            Book book = new Book("978-0684801469");
            book.setTitle("A Farewell to Arms");
            book.setAuthor("Ernest Hemmingway");
            book.setCopyrightYear(1929);
            Date authorBirthdate = new GregorianCalendar(1899, Calendar.JULY, 21).getTime();
            book.setAuthorBirthdate(authorBirthdate);

            em.persist(book);
        } finally {
            em.close();
        }

        try {
            em = emf.createEntityManager();
            Book book = new Book("978-0684830483");
            book.setTitle("For Whom the Bell Tolls");
            book.setAuthor("Ernest Hemmingway");
            book.setCopyrightYear(1940);
            Date authorBirthdate = new GregorianCalendar(1899, Calendar.JULY, 21).getTime();
            book.setAuthorBirthdate(authorBirthdate);

            em.persist(book);
        } finally {
            em.close();
        }

        try {
            em = emf.createEntityManager();
            Query query = null;
            List<Book> results = null;

            // Query for all entities of a kind
            query = em.createQuery("SELECT b FROM Book b");
            out.println("<p>Every book:</p><ul>");
            results = (List<Book>) query.getResultList();
            for (Book b : results) {
                out
                        .println("<li><i>" + b.getTitle() + "</i>, " + b.getAuthor() + ", " + b.getCopyrightYear()
                                + "</li>");
            }
            out.println("</ul>");

            // Query with a property filter
            query = em.createQuery("SELECT b FROM Book b WHERE copyrightYear >= :earliestYear");
            query.setParameter("earliestYear", 1937);
            out.println("<p>Every book published in or after 1937:</p><ul>");
            results = (List<Book>) query.getResultList();
            for (Book b : results) {
                out
                        .println("<li><i>" + b.getTitle() + "</i>, " + b.getAuthor() + ", " + b.getCopyrightYear()
                                + "</li>");
            }
            out.println("</ul>");

            // Getting just the first result of a query
            query = em.createQuery("SELECT b FROM Book b WHERE title = \"A Farewell to Arms\"");
            Book singleResult = (Book) query.getSingleResult();
            if (singleResult != null) {
                out.println("<p>Found: <i>" + singleResult.getTitle() + "</i>, " + singleResult.getAuthor() + "</p>");
            } else {
                out.println("<p>Could not find that book I was looking for...</p>");
            }

            // Getting specific results in the result list
            query = em.createQuery("SELECT b FROM Book b");
            out.println("<p>Books #3-#4:</p><ul>");
            query.setFirstResult(2);
            query.setMaxResults(2);
            results = (List<Book>) query.getResultList();
            for (Book b : results) {
                out
                        .println("<li><i>" + b.getTitle() + "</i>, " + b.getAuthor() + ", " + b.getCopyrightYear()
                                + "</li>");
            }
            out.println("</ul>");

            // A keys-only query
            query = em.createQuery("SELECT isbn FROM Book b");
            out.println("<p>Keys-only query:</p><ul>");
            List<String> resultKeys = (List<String>) query.getResultList();
            for (String k : resultKeys) {
                out.println("<li>" + k + "</li>");
            }
            out.println("</ul>");

            // JPA field selection
            query = em.createQuery("SELECT isbn, title, author FROM Book");
            out.println("<p>Field selection:</p><ul>");
            List<Object[]> resultsFields = (List<Object[]>) query.getResultList();
            for (Object[] result : resultsFields) {
                String isbn = (String) result[0];
                String title = (String) result[1];
                String author = (String) result[2];

                out.println("<li><i>" + title + "</i>, " + author + " (" + isbn + ")</li>");
            }
            out.println("</ul>");

            query = em.createQuery("DELETE FROM Book b");
            query.executeUpdate();
            out.println("<p>Entities deleted.</p>");

        } finally {
            em.close();
        }

        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSSSSS");
        fmt.setTimeZone(new SimpleTimeZone(0, ""));
        out.println("<p>The time is: " + fmt.format(new Date()) + "</p>");
    }
}
