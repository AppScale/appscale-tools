package bookjpa;

import java.util.Date;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import com.google.appengine.api.datastore.Key;

@Entity
public class Book {
    // Using Long as the type of the ID works for system-assigned IDs,
    // but not for app-assigned key names.  Also, an additional field
    // is needed to support ancestors.  Using datastore.Key as the ID
    // field type supports all features of keys.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Key key;

    private String title;
    private String author;
    private int copyrightYear;
    private Date authorBirthdate;

    public Key getKey() {
        return key;
    }

    public String getTitle() {
        return title;
    }
    public void setTitle(String title) {
        this.title = title;
    }

    public String getAuthor() {
        return author;
    }
    public void setAuthor(String author) {
        this.author = author;
    }

    public int getCopyrightYear() {
        return copyrightYear;
    }
    public void setCopyrightYear(int copyrightYear) {
        this.copyrightYear = copyrightYear;
    }

    public Date getAuthorBirthdate() {
        return authorBirthdate;
    }
    public void setAuthorBirthdate(Date authorBirthdate) {
        this.authorBirthdate = authorBirthdate;
    }
}
