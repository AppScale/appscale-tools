import re
import wsgiref.handlers

from google.appengine.api.appscale.ec2 import ec2

from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

class Main(webapp.RequestHandler):
  def get(self):
    user = users.get_current_user()
    if user is not None:
      response = "You are logged in as " + user.nickname() + ".<br />"
      response += "Is that <a href='" + users.create_logout_url("/") + "'>not you?</a><br /><br />"
    else:
      response = "You are not logged in yet.<br />"
      response += "Would you <a href='" + users.create_login_url("/describeinstances") + "'>like to?</a><br /><br />"

    if users.is_current_user_capable("ec2_api"):
      response += "You are authorized to use the EC2 API."
    else:
      response += "You are NOT authorized to use the EC2 API."

    self.response.out.write(template.render('index.html',
                                            {'tool': 'Welcome!',
                                             'result': response}))

class DescribeInstances(webapp.RequestHandler):
  def get(self):
    response = ec2.ec2_describe_instances().replace("\n", "<br /><br />")
    if response == "":
      response = "No instances are currently running."
    self.response.out.write(template.render('index.html',
                                            {'tool': 'EC2 Describe Instances',
                                             'result': response}))

class RunInstances(webapp.RequestHandler):
  def get(self):
    opts = {"machine":"emi-2DA1127F", "t":"m1.large"}
    response = ec2.ec2_run_instances(opts).replace("\n", "<br /><br />")
    self.response.out.write(template.render('index.html',
                                            {'tool': 'EC2 Run Instances',
                                             'result': response}))

class TerminateInstances(webapp.RequestHandler):
  def get(self):
    opts = {"ids":["i-54EA0A7A"]}
    response = ec2.ec2_terminate_instances(opts).replace("\n", "<br /><br />")
    self.response.out.write(template.render('index.html',
                                            {'tool': 'EC2 Terminate Instances',
                                             'result': response}))

class AddKeypair(webapp.RequestHandler):
  def get(self):
    opts = {"key":"barbar"}
    response = ec2.ec2_add_keypair(opts).replace("\n", "<br /><br />")
    self.response.out.write(template.render('index.html',
                                            {'tool': 'EC2 Add Keypair',
                                             'result': response}))

class DeleteKeypair(webapp.RequestHandler):
  def get(self):
    opts = {"key":"barbar"}
    response = ec2.ec2_delete_keypair(opts).replace("\n", "<br /><br />")
    self.response.out.write(template.render('index.html',
                                            {'tool': 'EC2 Delete Keypair',
                                             'result': response}))

class DescribeAvailabilityZones(webapp.RequestHandler):
  def get(self):
    opts = {"euca":"verbose"} # for euca, to get the max boxen available
    response = ec2.ec2_describe_availability_zones(opts).replace("\n", "<br /><br />")
    self.response.out.write(template.render('index.html',
                                            {'tool': 'EC2 Describe Availability Zones',
                                             'result': response}))

class DescribeImages(webapp.RequestHandler):
  def get(self):
    response = ec2.ec2_describe_images().replace("\n", "<br /><br />") 
    self.response.out.write(template.render('index.html',
                                            {'tool': 'EC2 Describe Images',
                                             'result': response}))

class RebootInstances(webapp.RequestHandler):
  def get(self):
    opts = {"ids":["i-558E0968"]}
    response = ec2.ec2_reboot_instances(opts).replace("\n", "<br /><br />")
    self.response.out.write(template.render('index.html',
                                            {'tool': 'EC2 Reboot Instances',
                                             'result': response}))

class TerminateAllInstances(webapp.RequestHandler):
  def get(self):
    response = ec2.ec2_describe_instances()
    images_up = re.findall('\ti-[\d\w]+\t', response)
    opts = {"ids":images_up}
    response = ec2.ec2_terminate_instances(opts).replace("\n", "<br /><br />")
    self.response.out.write(template.render('index.html',
                                            {'tool': 'Terminate all instances',
                                             'result': response}))

class UploadCreds(webapp.RequestHandler):
  def get(self):
    user = users.get_current_user()
    response = "You are logged in as " + user.nickname() + ".<br />"
    response += "Is that <a href='" + users.create_logout_url("/") + "'>not you?</a><br /><br />"
    response += "Please upload your credentials:<br /><br />"
    response += "<form action='upload' enctype='multipart/form-data' method='post'>"
    response += "<div><label>Certificate:</label><input type='file' name='ec2_cert'/></div><br />"
    response += "<div><label>Private Key:</label><input type='file' name='ec2_pk'/></div><br />"
    response += "<div><label>EC2 URL:</label><input type='text' name='ec2_url'/></div><br />"
    response += "<div><label>S3 URL:</label><input type='text' name='s3_url'/></div><br />"
    response += "<div><label>EC2 ACCESS KEY:</label><input type='text' name='ec2_access_key'/></div><br />"
    response += "<div><label>EC2 SECRET KEY:</label><input type='text' name='ec2_secret_key'/></div><br />"
    response += "<div><input type='submit' value='Upload'></div>"
    response += "</form>"
    self.response.out.write(template.render('index.html',
                                            {'tool': 'Upload your credentials',
                                            'result': response}))
  def post(self):
    cert = self.request.get("ec2_cert") 
    pk = self.request.get("ec2_pk")
    ec2_url = self.request.get("ec2_url")
    s3_url = self.request.get("s3_url")
    ec2_access_key = self.request.get("ec2_access_key")
    ec2_secret_key = self.request.get("ec2_secret_key")

    user = users.get_current_user()
    response = "Please log in and try again."
    if user:
      ec2.write_ec2_creds(cert, pk, ec2_url, s3_url, ec2_access_key, ec2_secret_key)
      response = "Your credentials were successfully uploaded."
    self.response.out.write(template.render('index.html',
                                            {'tool': 'Credentials uploaded',
                                             'result': response}))

class DescribeCreds(webapp.RequestHandler):
  def get(self):
    user = users.get_current_user()
    cert = str(ec2.get_ec2_cert()).replace("\n", "<br />")
    pk = str(ec2.get_ec2_pk()).replace("\n", "<br />")
    ec2_url = str(ec2.get_ec2_url()).replace("\n", "<br />")
    s3_url = str(ec2.get_s3_url()).replace("\n", "<br />")
    ec2_access_key = str(ec2.get_ec2_access_key()).replace("\n", "<br />")
    ec2_secret_key = str(ec2.get_ec2_secret_key()).replace("\n", "<br />")

    response = "Credentials for the user " + user.nickname() + " are:<br /><br />"
    response += "Certificate:<br />" + cert + "<br /><br />"
    response += "Private Key:<br />" + pk + "<br /><br />"
    response += "EC2 URL:<br />" + ec2_url + "<br /><br />"
    response += "S3 URL:<br />" + s3_url + "<br /><br />"
    response += "EC2 ACCESS KEY:<br />" + ec2_access_key + "<br /><br />"
    response += "EC2 SECRET KEY:<br />" + ec2_secret_key + "<br /><br />"

    self.response.out.write(template.render('index.html',
                                            {'tool': 'Show my credentials',
                                             'result': response}))

class RemoveCreds(webapp.RequestHandler):
  def get(self):
    user = users.get_current_user()
    if user:
      ec2.remove_ec2_creds()
      response = "Credentials for the user " + user.nickname() + " have been successfully removed."
    self.response.out.write(template.render('index.html',
                                            {'tool': 'Credentials removed',
                                             'result': response}))

def main():
  wsgiref.handlers.CGIHandler().run(webapp.WSGIApplication([
    ('/', Main),
    ('/describeinstances', DescribeInstances),
    ('/run', RunInstances),
    ('/terminate', TerminateInstances),
    ('/addkeypair', AddKeypair),
    ('/deletekeypair', DeleteKeypair),
    ('/describeavailabilityzones', DescribeAvailabilityZones),
    ('/describeimages', DescribeImages),
    ('/rebootinstances', RebootInstances),
    ('/terminateall', TerminateAllInstances),
    ('/upload', UploadCreds),
    ('/describecreds', DescribeCreds),
    ('/remove', RemoveCreds)
  ]))

if __name__ == '__main__':
  main()
