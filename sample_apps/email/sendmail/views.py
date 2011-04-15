# Create your views here.
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from google.appengine.api import mail


def root(request):
        if request.method == 'POST':
                message = mail.EmailMessage(sender=request.POST["from"],
                                            subject=request.POST["subject"])

                message.to = request.POST["to"]
                message.body = request.POST["body"]
                message.send()
                return HttpResponse("""Sent mail! Click <a href ="/">here</a> to send one more""")
        else:
                html =  """<form action="/" enctype="multipart/form-data" method="post">
                <div><label>From:</label>
                <input type="text"" name="from"></textarea></div>
                <div><label>To:</label>
                <input type="text" name="to" rows="1" cols="60"></textarea></div>
                <div><label>Subject:</label></div>
                <div><textarea name="subject" rows="1" cols="60"></textarea></div>
                <div><label>Body:</label></div>
                <div><textarea name="body" rows="5" cols="60"></textarea></div>
                <div><input type="submit" value="Submit"></div>
                </form>
                </body>
                </html>"""
	        return HttpResponse(html)

