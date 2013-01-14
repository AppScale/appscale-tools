import commands
import os
import shutil
import uuid
from xml.dom import minidom
import yaml

__author__ = 'hiranya'

# When we try to ssh to other machines, we don't want to be asked
# for a password (since we always should have the right SSH key
# present), and we don't want to be asked to confirm the host's
# fingerprint, so set the options for that here.
SSH_OPTIONS = "-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o ConnectTimeout=4"

JAVA_AE_VERSION = '1.7.4'

class AppScaleToolsException(Exception):
  def __init__(self, msg, code=0):
    Exception.__init__(self, msg)
    self.code = code

def assert_commands_exist(commands):
  for command in commands:
    available = shell('which %s' % command)
    if not available:
      msg = 'Required command %s not available' % command
      raise AppScaleToolsException(msg)

def shell(command, status=False):
  if status:
    return commands.getstatusoutput(command)
  else:
    return commands.getoutput(command)

def diff(list1, list2):
  """
  Returns the list of entries that are present in list1 but not
  in list2.

  Args:
    list1 A list of elements
    list2 Another list of elements

  Returns:
    A list of elements unique to list1
  """
  return sorted(set(list1) - set(list2))

def flatten(obj):
  if isinstance(obj, str):
    return [ obj ]
  elif isinstance(obj, list):
    output = []
    for item in obj:
      output += flatten(item)
    return output
  else:
    msg = 'Object of type %s cannot be flattened' % type(obj)
    raise AppScaleToolsException(msg)

def generate_rsa_key(dir, keyname):
  private_key = os.path.join(dir, keyname)
  backup_key = os.path.join(dir, keyname + '.key')
  public_key = os.path.join(dir, keyname + '.pub')

  if not os.path.exists(private_key) and not os.path.exists(public_key):
    print shell("ssh-keygen -t rsa -N '' -f %s" % private_key)

  os.chmod(private_key, 0600)
  os.chmod(public_key, 0600)
  shutil.copyfile(private_key, backup_key)
  return private_key, public_key, backup_key

def ssh_copy_id(ip, path, auto, expect_script, password):
  heading = '\nExecuting ssh-copy-id for host : ' + ip
  print heading
  print '=' * len(heading)

  if auto:
    command = '{%s} root@{%s} {%s} {%s}' % (expect_script, ip, path, password)
  else:
    command = 'ssh-copy-id -i {%s} root@{%s}' % (path, ip)

  status, output = shell(command, status=True)
  print output
  if not status:
    msg = 'Error while executing ssh-copy-id on %s' % ip
    raise AppScaleToolsException(msg)

def get_random_alpha_numeric():
  return str(uuid.uuid4()).replace('-', '')

def generate_secret_key(path):
  secret_key = get_random_alpha_numeric()
  full_path = os.path.expanduser(path)
  secret_file = open(full_path, 'w')
  secret_file.write(secret_key)
  secret_file.close()
  return secret_key

def is_ssh_key_valid(ssh_key, host):
  command = "ssh -i %s %s 2>&1 root@%s 'touch /tmp/foo'; "\
            "echo $? " % (ssh_key, SSH_OPTIONS, host)
  status, output = shell(command, status=True)
  return status is 0 and output == '0'

def scp_file(source, destination, host, ssh_key):
  command = 'scp -i %s %s 2>&1 '\
            '%s root@%s:%s' % (ssh_key, SSH_OPTIONS, source, host, destination)
  shell(command, status=True)

def run_remote_command(command, host, ssh_key):
  remote_command = "ssh -i %s %s root@%s '%s > /dev/null "\
                   "2>&1 &'" % (ssh_key, SSH_OPTIONS, host, command)
  shell(remote_command, status=True)

def create_temp_dir():
  temp_dir = '/tmp/' + get_random_alpha_numeric()
  if os.path.exists(temp_dir):
    shutil.rmtree(temp_dir)
  os.mkdir(temp_dir)
  return temp_dir

def get_app_info(file, database):
  name = None
  app_file = None
  language = None

  full_path = os.path.abspath(os.path.expanduser(file))
  if not os.path.exists(full_path):
    msg = 'Specified application file: %s does not exist' % file
    raise AppScaleToolsException(msg)

  temp_dir = create_temp_dir()

  # TODO: Move app

  if os.path.exists(os.path.join(temp_dir, 'app.yaml')):
    yaml_file = open(os.path.join(temp_dir, 'app.yaml'))
    app_descriptor = yaml.load(yaml_file)
    yaml_file.close()
    name = app_descriptor['application']
    language = app_descriptor['runtime']
    if os.path.isdir(full_path):
      temp_dir2 = create_temp_dir()
      shell('cd /tmp/%s; tar -czf ../%s/%s.tar.gz .' % (temp_dir, temp_dir2, name))
      app_file = '/tmp/%s/%s.tar.gz' % (temp_dir2, name)
    else:
      app_file = full_path
  elif os.path.exists(os.path.join(temp_dir, 'war/WEB-INF/appengine-web.xml')):
    language = 'java'
    xml = minidom.parse(os.path.join(temp_dir, 'war/WEB-INF/appengine-web.xml'))
    application_nodes = xml.getElementsByTagName('application')
    if application_nodes:
      text_node = application_nodes[0].childNodes
      if text_node:
        name = text_node[0].data

    thread_safe = False
    thread_safe_nodes = xml.getElementsByTagName('threadsafe')
    if thread_safe_nodes:
      text_node = thread_safe_nodes[0].childNodes
      if text_node and text_node.data == 'true':
        thread_safe = True

    if not thread_safe:
      msg = 'Java application has not been marked as thread safe'
      raise AppScaleToolsException(msg)

    sdk_file = 'war/WEB-INF/lib/appengine-api-1.0-sdk-%s.jar' % JAVA_AE_VERSION
    sdk_file_path = os.path.join(full_path, sdk_file)
    if not os.path.exists(sdk_file_path):
      msg = 'Unsupported Java appengine version. Please recompile and ' \
            'repackage your app with Java appengine %s' % JAVA_AE_VERSION
      raise AppScaleToolsException(msg)

    temp_dir2 = create_temp_dir()
    shell('cd /tmp/%s; tar -czf ../%s/%s.tar.gz .' % (temp_dir, temp_dir2, name))
    app_file = '/tmp/%s/%s.tar.gz' % (temp_dir2, name)
  else:
    msg = 'Failed to find a valid app descriptor in %s' % file
    shutil.rmtree(temp_dir)
    raise AppScaleToolsException(msg)

  if name is None or app_file is None or language is None:
    msg = 'Failed to extract required metadata from application descriptor'
    raise AppScaleToolsException(msg)

  disallowed = ["none", "auth", "login", "new_user", "load_balancer"]
  if name in disallowed:
    raise AppScaleToolsException('Application name %s is reserved' % name)

  for ch in name:
    if not ch.islower() and not ch.isdigit() and ch != '-':
      raise AppScaleToolsException('Application names may only contain lower '
                                   'case letters, digits and hyphens')
    elif ch == '-' and database == 'hypertable':
      raise AppScaleToolsException('Application name may not contain hyphens '
                                   'when used with Hypertable')
  return name, app_file, language

def copy_appscale_source(source, host, ssh_key):
  local = os.path.abspath(os.path.expanduser(source))
  if not os.path.exists(local):
    msg = 'Unable to find AppScale source at:', source
    raise AppScaleToolsException(msg)

  lib = "%s/lib" % local
  controller = "%s/AppController" % local
  app_manager = "%s/AppManager" % local
  server = "%s/AppServer" % local
  load_balancer = "%s/AppLoadBalancer" % local
  monitoring = "%s/AppMonitoring" % local
  app_db = "%s/AppDB" % local
  neptune = "%s/Neptune" % local
  iaas_manager = "%s/InfrastructureManager" % local

  print 'Copying over local copy of AppScale from', source
  shell("rsync -e 'ssh -i %s' -arv %s/* "
        "root@%s:/root/appscale/AppController" % (ssh_key, controller, host))
  shell("rsync -e 'ssh -i %s' -arv %s/* "
        "root@%s:/root/appscale/lib" % (ssh_key, lib, host))
  shell("rsync -e 'ssh -i %s' -arv %s/* "
        "root@%s:/root/appscale/AppManager" % (ssh_key, app_manager, host))
  shell("rsync -e 'ssh -i %s' -arv %s/* "
        "root@%s:/root/appscale/AppServer" % (ssh_key, server, host))
  shell("rsync -e 'ssh -i %s' -arv %s/* "
        "root@%s:/root/appscale/AppLoadBalancer" % (ssh_key, load_balancer, host))
  shell("rsync -e 'ssh -i %s' -arv %s/* "
        "root@%s:/root/appscale/AppMonitoring" % (ssh_key, monitoring, host))
  shell("rsync -e 'ssh -i %s' -arv --exclude='logs/*' --exclude='hadoop-*' "
        "--exclude='hbase/hbase-*' --exclude='voldemort/voldemort/*' "
        "--exclude='cassandra/cassandra/*' %s/* "
        "root@%s:/root/appscale/AppDB" % (ssh_key, app_db, host))
  shell("rsync -e 'ssh -i %s' -arv %s/* "
        "root@%s:/root/appscale/Neptune" % (ssh_key, neptune, host))
  shell("rsync -e 'ssh -i %s' -arv %s/* "
        "root@%s:/root/appscale/InfrastructureManager" % (ssh_key, iaas_manager, host))
