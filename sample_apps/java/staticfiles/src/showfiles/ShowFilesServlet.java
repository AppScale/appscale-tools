package showfiles;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import javax.servlet.http.*;

@SuppressWarnings("serial")
public class ShowFilesServlet extends HttpServlet {
    public void doGet(HttpServletRequest req,
                      HttpServletResponse resp)
        throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();

        File appDir = new File(".");
        String dirContents[] = appDir.list();
        if (dirContents == null) {
            out.println("<p>There was a problem getting the app directory.</p>");
        } else {
            out.println("<p>The following files and directories are in the app's " +
                        "root directory on the application server:</p><pre>");
            for (int i = 0; i < dirContents.length; i++) {
                out.println(dirContents[i]);
            }
            out.println("</pre>");
        }

        out.println("<p>The \"static\" directory appears in this list in the " +
                    "development server, but not when running on App Engine.</p>" +
                    "<p>Links to static files:</p><ul>" +
                    "<li><a href=\"staticexpires.txt\">staticexpires.txt</a> (text)</li>" +
                    "<li><a href=\"static/statictext.txt\">static/statictext.txt</a> (text)</li>" +
                    "<li><a href=\"static/statictext.xxx\">static/statictext.xxx</a> (text)</li>" +
                    "<li><a href=\"static/staticdownload.yyy\">static/staticdownload.yyy</a> (download)</li>" +
                    "</ul>");

        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSSSSS");
        fmt.setTimeZone(new SimpleTimeZone(0, ""));
        out.println("<p>" + fmt.format(new Date()) + "</p>");
    }
}
