package guestbook;

import java.io.IOException;

import javax.jdo.PersistenceManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DeleteServlet extends HttpServlet {

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
        Long id = (long)-1;
		try{
			id = Long.parseLong(req.getParameter("id"));
		    PersistenceManager pm = PMF.get().getPersistenceManager();
		        
		    try{
		    	pm.deletePersistent(pm.getObjectById(Greeting.class,id));
		    	resp.sendRedirect("/guestbook.jsp");     
		    }
		    catch(Exception e){
		      	resp.sendRedirect("/guestbook.jsp?fail="+id);     
		    }
        }
		catch(NumberFormatException e){
			resp.sendRedirect("/guestbook.jsp?fail="+req.getParameter("id"));   
		}
  //      System.out.println(id);
  
    
	}

}
