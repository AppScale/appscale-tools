from google.appengine.api import users

print "Content-Type: text/plain"

user = users.get_current_user()

if user:
    print "Welcome, %s!" % user.nickname()
    if users.is_current_user_admin():
        print "You win admin rights! =)"
        print "<a href=\"/admin/\">Go to admin area</a>"
    else:
      print "You are not an admin."
else:
   print "You are not logged in"
