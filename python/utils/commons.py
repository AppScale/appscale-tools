import commands
import getpass
import hashlib
import os
import re
import shutil
import socket
import traceback
import uuid
from xml.dom import minidom
import time
import OpenSSL
import yaml

__author__ = 'hiranya'

# When we try to ssh to other machines, we don't want to be asked
# for a password (since we always should have the right SSH key
# present), and we don't want to be asked to confirm the host's
# fingerprint, so set the options for that here.
SSH_OPTIONS = "-o NumberOfPasswordPrompts=0 -o StrictHostkeyChecking=no -o ConnectTimeout=4"

JAVA_AE_VERSION = '1.7.4'

PYTHON_APP_DESCRIPTOR = 'app.yaml'
JAVA_APP_DESCRIPTOR = 'war/WEB-INF/appengine-web.xml'

RESERVED_APP_NAMES = ( 'none', 'auth', 'login', 'new_user', 'load_balancer' )
SUPPORTED_LANGUAGES = ( 'python', 'python27', 'java', 'go' )

class AppScaleToolsException(Exception):
  def __init__(self, msg, code=0):
    Exception.__init__(self, msg)
    self.code = code

class Logger(object):
  """
  An instance of this class can be used to log various events, errors and debug
  information during the operation of AppScaleTools. This class is implemented
  as a singleton. Use the commons.get_logger() method to obtain an instance
  of this class. This class supports 2 level of logging. Info level messages
  are always logged and displayed on the console. Therefore any message logged
  in the info level becomes a part of the program's standard output. Verbose
  level log messages are not logged to the console by default. The is_verbose
  flag must be set on the Logger instance for the verbose log messages to be
  printed on the console.
  """

  _instance = None

  def __new__(cls, *args, **kwargs):
    """
    Create a singleton Logger instance.
    """
    if not cls._instance:
      cls._instance = super(Logger, cls).__new__(cls, *args, **kwargs)
      cls._instance.is_verbose = False
    return cls._instance

  def set_verbose(self, verbose):
    """
    Use this method to set/unset the is_verbose flag on this Logger instance.

    Args:
      verbose Boolean value which will be assigned to the is_verbose flag.
    """
    self.is_verbose = verbose

  def info(self, msg):
    """
    Log the given message in the info level. Info level messages are always
    directly logged to the console. Hence this method can be used to any
    message that should be printed on the console as a part of the standard
    output of the application.

    Args:
      msg The message to be logged
    """
    print msg

  def verbose(self, msg):
    """
    Log the given message in the verbose level. Verbose level messages are not
    always directly logged to the console. Whether they are printed or not
    depends on the current value of the is_verbose flag. Hence this method can
    be used to any debug level message.

    Args:
      msg The message to be logged
    """
    if self.is_verbose:
      print '[verbose]', msg

def get_logger(verbose=None):
  """
  Obtain an instance of the Logger singleton. Optionally the value of the
  is_verbose flag can also be set via this method by passing in the verbose
  argument.

  Args:
    verbose If set to a boolean value, that value will be assigned to the
            is_verbose flag on the Logger, before the Logger is returned.
            By default this is set to None and hence it returns the current
            Logger instance as it is.

  Returns:
    The singleton Logger instance.
  """
  logger = Logger()
  if verbose is not None:
    logger.set_verbose(verbose)
  return logger

def assert_commands_exist(commands):
  """
  Checks and asserts that all the commands in the given list are available
  in the underlying operating system.

  Args:
    commands  A list of string commands to test

  Raises:
    AppScaleToolsException  If at least one of the input commands are not
                            available in the system
  """
  for command in commands:
    available = shell('which %s' % command)
    if not available:
      error('Required command %s not available' % command)

def shell(command, status=False):
  """
  Execute the given command as if it was executed in a Unix shell and
  return the output.

  Args:
    command The command to execute as a string
    status  If True the method will also return the return status of the
            command execution. Defaults to False.

  Returns:
    The output of the command as a string or a tuple of the form
    (return_status, output) where return_status is the integer status code
    resulted from the execution and output is the string output of the
    command.
  """
  logger = get_logger()
  if logger.is_verbose: logger.verbose('shell> %s' % command)
  ret_val, output = commands.getstatusoutput(command)
  if logger.is_verbose:
    logger.verbose('Command exited with status code %s' % ret_val)
    logger.verbose('Command output: %s' % output)
  if status:
    return ret_val, output
  else:
    return output

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
  """
  Flatten the input object into a single list. Ideal for reducing a list
  of lists into a single flat list.

  Args:
    obj Input object to be flattened

  Returns:
    Flattened list containing all the members of the input object
  """
  if isinstance(obj, str):
    return [ obj ]
  elif isinstance(obj, list):
    output = []
    for item in obj:
      output += flatten(item)
    return output
  else:
    error('Object of type %s cannot be flattened' % type(obj))

def generate_rsa_key(dir, keyname):
  private_key = os.path.join(dir, keyname)
  backup_key = os.path.join(dir, keyname + '.key')
  public_key = os.path.join(dir, keyname + '.pub')

  logger = get_logger()
  if not os.path.exists(private_key) and not os.path.exists(public_key):
    logger.info(shell("ssh-keygen -t rsa -N '' -f %s" % private_key))

  os.chmod(private_key, 0600)
  os.chmod(public_key, 0600)
  shutil.copyfile(private_key, backup_key)
  return private_key, public_key, backup_key

def ssh_copy_id(ip, path, auto, expect_script, password):
  logger = get_logger()
  heading = '\nExecuting ssh-copy-id for host : ' + ip
  logger.info(heading)
  logger.info('=' * len(heading))

  if auto:
    command = '%s root@%s %s %s' % (expect_script, ip, path, password)
  else:
    command = 'ssh-copy-id -i %s root@%s' % (path, ip)

  status, output = shell(command, status=True)
  logger.info(output)
  if not status is 0:
    error('Error while executing ssh-copy-id on %s' % ip)

def get_random_alpha_numeric():
  return str(uuid.uuid4()).replace('-', '')

def generate_secret_key(path):
  logger = get_logger()
  secret_key = get_random_alpha_numeric()
  full_path = os.path.expanduser(path)
  if logger.is_verbose:
    logger.verbose('Generated secret key %s' % secret_key)
    logger.verbose('Saving the secret key to: %s' % full_path)
  secret_file = open(full_path, 'w')
  secret_file.write(secret_key + '\n')
  secret_file.close()
  return secret_key

def is_ssh_key_valid(ssh_key, host):
  """
  Checks whether the given SSH key can be used to login to the specified host.

  Args:
    ssh_key SSH key to test and validate
    host    Target host to which the application attempts to login

  Returns:
    Boolean value indicating whether the SSH key is valid or not
  """
  command = "ssh -i %s %s 2>&1 root@%s 'touch /tmp/foo'; "\
            "echo $? " % (ssh_key, SSH_OPTIONS, host)
  status, output = shell(command, status=True)
  return status is 0 and output == '0'

def scp_file(source, destination, host, ssh_key, download=False):
  """
  Copy the specified file from the local file system to a remote file system
  using the SCP utility.

  source      Path to the local file
  destination Path in the remote file system
  host        Remote host address
  ssh_key     SSH key to login to the remote host
  download    Use SCP to download a remote file instead of uploading a local
              file. Default is False.
  """
  if not download:
    command = 'scp -i %s %s 2>&1 '\
              '%s root@%s:%s' % (ssh_key, SSH_OPTIONS, source, host, destination)
  else:
    command = 'scp -i %s %s 2>&1 ' \
              'root@%s:%s %s' % (ssh_key, SSH_OPTIONS, host, source, destination)
  shell(command, status=True)

def run_remote_command(command, host, ssh_key, user='root'):
  remote_command = "ssh -i %s %s %s@%s '%s > /dev/null "\
                   "2>&1 &'" % (ssh_key, SSH_OPTIONS, user, host, command)
  return shell(remote_command, status=True)

def remote_location_exists(location, host, ssh_key):
  command = "ssh -i %s %s root@%s 'ls %s'" % (
    ssh_key, SSH_OPTIONS, host, location)
  status, output = shell(command, status=True)
  return status is 0

def get_temp_dir(create=True):
  temp_dir = '/tmp/' + get_random_alpha_numeric()
  if os.path.exists(temp_dir):
    shutil.rmtree(temp_dir)
  if create:
    os.makedirs(temp_dir)
  return temp_dir

def get_dom_value(dom, node):
  application_nodes = dom.getElementsByTagName(node)
  if application_nodes:
    text_node = application_nodes[0].childNodes
    if text_node:
      return text_node[0].data
  return None

def get_app_info(file, database):
  app_name, app_file, language = None, None, None
  if not file:
    return app_name, app_file, language

  full_path = os.path.abspath(os.path.expanduser(file))
  if not os.path.exists(full_path):
    error('Specified application file: %s does not exist' % file)

  if os.path.isdir(full_path):
    temp_dir = get_temp_dir(create=False)
    shutil.copytree(full_path, temp_dir)
  else:
    temp_dir = get_temp_dir()
    shutil.copy(full_path, temp_dir)
    file_name = os.path.basename(full_path)
    cmd = 'cd %s; tar zxvfm %s 2>&1' % (temp_dir, file_name)
    status, output = shell(cmd, status=True)
    if not status is 0:
      error('Error while extracting ' + file_name)

  if os.path.exists(os.path.join(temp_dir, PYTHON_APP_DESCRIPTOR)):
    yaml_file = open(os.path.join(temp_dir, PYTHON_APP_DESCRIPTOR))
    app_descriptor = yaml.load(yaml_file)
    yaml_file.close()
    app_name = app_descriptor.get('application')
    language = app_descriptor.get('runtime')
  elif os.path.exists(os.path.join(temp_dir, JAVA_APP_DESCRIPTOR)):
    xml = minidom.parse(os.path.join(temp_dir, JAVA_APP_DESCRIPTOR))
    app_name = get_dom_value(xml, 'application')
    language = 'java'
    thread_safe = get_dom_value(xml, 'threadsafe')
    if thread_safe != 'true':
      error('Java application has not been marked as thread safe')

    sdk_file = 'war/WEB-INF/lib/appengine-api-1.0-sdk-%s.jar' % JAVA_AE_VERSION
    sdk_file_path = os.path.join(full_path, sdk_file)
    if not os.path.exists(sdk_file_path):
      error('Unsupported Java appengine version. Please recompile and ' \
            'repackage your app with Java appengine %s' % JAVA_AE_VERSION)
  else:
    shutil.rmtree(temp_dir)
    error('Failed to find a valid app descriptor in %s' % file)

  if app_name is None or language is None:
    error('Failed to extract required metadata from application descriptor')
  elif not language in SUPPORTED_LANGUAGES:
    error('Application runtime %s is not supported' % language)

  if app_name in RESERVED_APP_NAMES:
    error('Application name %s is reserved' % app_name)

  for ch in app_name:
    if not ch.islower() and not ch.isdigit() and ch != '-':
      error('Application names may only contain lower case letters, '
            'digits and hyphens')
    elif ch == '-' and database == 'hypertable':
      error('Application name may not contain hyphens when used '
            'with Hypertable')

  if os.path.isdir(full_path):
    temp_dir2 = get_temp_dir()
    file_name = '%s.tar.gz' % app_name
    command = 'cd %s; tar -czf ../%s/%s .' % (
      temp_dir, os.path.basename(temp_dir2), file_name)
    shell(command)
    app_file = os.path.join(temp_dir2, file_name)
  else:
    app_file = full_path

  return app_name, app_file, language

def copy_appscale_source(source, host, ssh_key):
  local = os.path.abspath(os.path.expanduser(source))
  if not os.path.exists(local):
    error('Unable to find AppScale source at: %s' % source)

  lib = "%s/lib" % local
  controller = "%s/AppController" % local
  app_manager = "%s/AppManager" % local
  server = "%s/AppServer" % local
  load_balancer = "%s/AppLoadBalancer" % local
  monitoring = "%s/AppMonitoring" % local
  app_db = "%s/AppDB" % local
  neptune = "%s/Neptune" % local
  iaas_manager = "%s/InfrastructureManager" % local

  logger = get_logger()
  logger.info('Copying over local copy of AppScale from %s' % source)
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

def generate_certificate(path, keyname):
  """
  Generate a RSA private key and a X509 certificate.

  Args:
    path  Directory where the generated artifacts should be saved
    keyname Used as a prefix to name the key and certificate files

  Returns:
    A tuple containing the paths to the generated private key file and
    X509 certificate.
  """
  private_key = OpenSSL.crypto.PKey()
  private_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
  cert = OpenSSL.crypto.X509()
  cert.get_subject().C = 'US'
  cert.get_subject().ST = 'Foo'
  cert.get_subject().L = 'Bar'
  cert.get_subject().O = 'AppScale'
  cert.get_subject().OU = 'User'
  cert.get_subject().CN = 'appscale.com'
  cert.set_issuer(cert.get_subject())
  cert.set_pubkey(private_key)
  cert.set_serial_number(int(time.time()))
  cert.gmtime_adj_notBefore(0)
  cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
  cert.set_serial_number(int(time.time()))

  cert.sign(private_key, 'sha1')

  pk_path = os.path.join(path, keyname + '-key.pem')
  cert_path = os.path.join(path, keyname + '-cert.pem')

  pk_file = open(pk_path, 'w')
  pk_file.write(OpenSSL.crypto.dump_privatekey(
    OpenSSL.crypto.FILETYPE_PEM, private_key))
  pk_file.close()

  cert_file = open(cert_path, 'w')
  cert_file.write(OpenSSL.crypto.dump_certificate(
    OpenSSL.crypto.FILETYPE_PEM, cert))
  cert_file.close()

  return pk_path, cert_path

def prompt_for_user_credentials():
  """
  Prompts the user to enter a username, password pair for account creation
  purposes. The input string must be a valid email address and the method will
  automatically re-prompt upon detecting invalid inputs. The user will be
  prompted to enter the password twice for verification purposes.

  Returns:
    A tuple consisting of the username and password entered by the user
  """
  username, password = None, None
  logger = get_logger()
  while True:
    username = raw_input('Enter your desired admin e-mail address: ')
    email_regex = '^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$'
    if re.match(email_regex, username):
      break
    else:
      logger.info('Invalid e-mail address. Please try again.')

  while True:
    password = getpass.getpass('Enter new password: ')
    if len(password) < 6:
      logger.info('Password must be at least 6 characters long')
      continue
    password2 = getpass.getpass('Confirm password: ')
    if password != password2:
      logger.info('2 password entries do not match. Please try again.')
    else:
      break

  return username, password

def sha1_encrypt(string):
  """
  Apply SHA1 encryption on the input string.

  Args:
    string  String to be encrypted

  Returns:
    Hex digest of the SHA1 encrypted string
  """
  return hashlib.sha1(string).hexdigest()

def map_to_array(map):
  """
  Convert a map (dictionary) into list. Given a map {k1:v1, k2:v2,...kn:vn}
  this will return a list [k1,v1,k2,v2,...,kn,vn].

  Args:
    map A dictionary of objects

  Returns:
    A list containing all the keys and values in the input dictionary
  """
  list = []
  for k,v in map.items():
    list.append(k)
    list.append(v)
  return list

def error(msg, code=None, exception=None):
  logger = get_logger()
  if logger.is_verbose:
    if exception is None:
      logger.verbose(msg)
      stack = traceback.extract_stack()
      stack_string = ''.join(traceback.format_list(stack[:-1]))
      logger.verbose(stack_string)
    else:
      logger.verbose(str(exception))
      logger.verbose(traceback.format_exc())
  if code is None:
    raise AppScaleToolsException(msg)
  else:
    raise AppScaleToolsException(msg, code)

def is_port_open(host, port):
  logger = get_logger()
  try:
    sock = socket.socket()
    sock.connect((host, port))
    return True
  except Exception as exception:
    logger.verbose(str(exception))
    return False
