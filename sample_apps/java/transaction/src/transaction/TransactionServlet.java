package transaction;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.api.datastore.DatastoreFailureException;
import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.PreparedQuery;
import com.google.appengine.api.datastore.Query;
import com.google.appengine.api.datastore.Transaction;

@SuppressWarnings("serial")
public class TransactionServlet extends HttpServlet {
    private static final Logger log = Logger.getLogger(TransactionServlet.class.getName());

    // Hard code the message board name for simplicity. Could support
    // multiple boards by getting this from the URL.
    private String boardName = "messageBoard";

    public static String escapeHtmlChars(String inStr) {
        return inStr.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
    }

    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();

        DatastoreService ds = DatastoreServiceFactory.getDatastoreService();

        // Display information about a message board and its messages.
        Key boardKey = KeyFactory.createKey("MessageBoard", boardName);
        try {
            Entity messageBoard = ds.get(boardKey);
            long count = (Long) messageBoard.getProperty("count");
            resp.getWriter().println("<p>Latest messages posted to " + boardName + " (" + count + " total):</p>");

            Query q = new Query("Message", boardKey);
            PreparedQuery pq = ds.prepare(q);
            for (Entity result : pq.asIterable()) {
                resp.getWriter().println(
                        "<h3>" + escapeHtmlChars((String) result.getProperty("message_title")) + "</h3></p>"
                                + escapeHtmlChars((String) result.getProperty("message_text")) + "</p>");
            }
        } catch (EntityNotFoundException e) {
            resp.getWriter().println("<p>No messages.</p>");
        }

        // Display a web form for creating new messages.
        resp.getWriter().println(
                "<p>Post a message:</p>" + "<form action=\"/\" method=\"POST\">"
                        + "<label for=\"title\">Title:</label>"
                        + "<input type=\"text\" name=\"title\" id=\"title\" /><br />"
                        + "<label for=\"body\">Message:</label>"
                        + "<textarea name=\"body\" id=\"body\"></textarea><br />" + "<input type=\"submit\" />"
                        + "</form>");

        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSSSSS");
        fmt.setTimeZone(new SimpleTimeZone(0, ""));
        out.println("<p>The time is: " + fmt.format(new Date()) + "</p>");
    }

    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        // Save the message and update the board count in a
        // transaction, retrying up to 3 times.

        com.google.appengine.api.datastore.DatastoreService ds = DatastoreServiceFactory.getDatastoreService();

        String messageTitle = req.getParameter("title");
        String messageText = req.getParameter("body");
        Date postDate = new Date();

        int retries = 3;
        boolean success = false;
        while (!success && retries > 0) {
            --retries;

            Entity messageBoard;
            Transaction txn = ds.beginTransaction();
            try {
                Key boardKey;
                try {
                    boardKey = KeyFactory.createKey("MessageBoard", boardName);
                    messageBoard = ds.get(boardKey);

                } catch (EntityNotFoundException e) {
                    messageBoard = new Entity("MessageBoard", boardName);
                    messageBoard.setProperty("count", 0L);
                    boardKey = ds.put(messageBoard);
                }

                Entity message = new Entity("Message", boardKey);
                message.setProperty("message_title", messageTitle);
                message.setProperty("message_text", messageText);
                message.setProperty("post_date", postDate);
                ds.put(message);
                long count = (Long) messageBoard.getProperty("count");
                ++count;

                messageBoard.setProperty("count", count);
                ds.put(messageBoard);

                if (count == 3) {
                    log.info("throwing an exception");
                    throw new RuntimeException("count is 3");
                }
                log.info("Posting msg, updating count to " + count + "; " + retries + " retries remaining");

                txn.commit();

                // Break out of retry loop.
                success = true;

            } catch (DatastoreFailureException e) {
                // Allow retry to occur.
                log.info("retrying because of datastore failure");
            } catch (Throwable t) {
                t.printStackTrace();
                log.info("rolling back");
              
                txn.rollback();
            }
            // if do not rollback explicitly, skd will automatically rollback
        }

        if (!success) {
            resp.getWriter().println(
                    "<p>A new message could not be posted.  Try again later."
                            + "<a href=\"/\">Return to the board.</a></p>");
        } else {
            resp.sendRedirect("/");
        }
    }
}
