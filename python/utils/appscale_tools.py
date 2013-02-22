import getpass
import os
import shutil
from time import sleep
import yaml
from utils import commons, cli, cloud
from utils.app_controller_client import AppControllerClient
from utils.node_layout import NodeLayout
from utils.user_management_client import UserManagementClient

__author__ = 'hiranya'

APPSCALE_DIR = '~/.appscale'
VERSION = '1.6.5'

class AddKeyPairOptions:
  """
  An instance of this class should be used to hold the parameters passed
  into the add_key_pair operation.
  """

  def __init__(self, ips, keyname, auto=False, verbose=False):
    """
    Create a new instance of AddKeyPairOptions with the specified parameters.

    Args:
      ips     Path to an ips.yaml file describing the node layout
      keyname Name of the security key to be generated
      auto    If True, the add_key_pair operation would attempt to run the
              entire operation by itself, with minimum user interaction. Default
              is False.
      verbose If True will cause the add_key_pair operation to generate verbose
              output. Default is False.
    """
    self.ips = ips
    self.keyname = keyname
    self.auto = auto
    self.root_password = None
    self.verbose = verbose

class RunInstancesOptions:
  """
  An instance of this class should be used to hold the parameters passed
  into the run_instances operation.
  """

  def __init__(self):
    """
    Create a new instance of RunInstancesOptions with the default parameters.
    """
    self.infrastructure = None
    self.machine = None
    self.instance_type = None
    self.ips = None
    self.database = 'cassandra'
    self.min = None
    self.max = None
    self.keyname = 'appscale'
    self.group = 'appscale'
    self.scp = None
    self.file = None
    self.replication = None
    self.read_q = None
    self.write_q = None
    self.app_engines = 1
    self.auto_scale = False
    self.restore_from_tar = None
    self.restore_neptune_info = None
    self.username = None
    self.password = None
    self.testing = False
    self.verbose = False

  def validate(self):
    """
    Check and validate whether the parameter values set on this instance
    are semantically correct.

    Returns:
      A tuple of the form (NodeLayout, AppInfo) where AppInfo itself is a
      tuple containing application metadata. The AppInfo tuple takes on the
      form (app_name, app_file, language).

    Raises:
      AppScaleToolsException  If the validation logic detects a syntactic or
                              semantic fault with the provided parameters.
    """
    layout_options = {
      cli.OPTION_INFRASTRUCTURE : self.infrastructure,
      cli.OPTION_DATABASE : self.database,
      cli.OPTION_MIN_IMAGES : self.min,
      cli.OPTION_MAX_IMAGES : self.max,
      cli.OPTION_REPLICATION : self.replication,
      cli.OPTION_READ_FACTOR : self.read_q,
      cli.OPTION_WRITE_FACTOR : self.write_q
    }
    node_layout = NodeLayout(self.ips, layout_options)
    if self.infrastructure:
      cloud.validate(self.infrastructure, self.machine,
        self.instance_type, self.keyname)
    app_info = commons.get_app_info(self.file, self.database)
    return node_layout, app_info

def add_key_pair(options):
  """
  Generate a new cryptographic key pair on the local system and upload it
  to a set of remote machines. This enables the users and applications to
  login to each remote machine over SSH using public key authentication
  mode of SSH.

  Args:
    options An instance of AddKeyPairOptions class

  Raises:
    AppScaleToolsException If an error occurs while generating and uploading
                            the keys.
  """
  logger = commons.get_logger(options.verbose)
  node_layout = NodeLayout(options.ips)

  required_commands = [ 'ssh-keygen', 'ssh-copy-id' ]
  if options.auto:
    required_commands.append('expect')
  commons.assert_commands_exist(required_commands)

  appscale_dir = __get_appscale_dir()
  key_info = commons.generate_rsa_key(appscale_dir, options.keyname)
  pvt_key = key_info[0]
  public_key = key_info[1]

  if options.auto and options.root_password is None:
    options.root_password = getpass.getpass('Enter SSH password of root: ')

  for node in node_layout.nodes:
    commons.ssh_copy_id(node.id, pvt_key, options.auto,
      'sshcopyid', options.root_password)

  head_node = node_layout.get_head_node()
  commons.scp_file(pvt_key, '~/.ssh/id_dsa', head_node.id, pvt_key)
  commons.scp_file(public_key, '~/.ssh/id_rsa.pub', head_node.id, pvt_key)

  logger.info('A new ssh key has been generated for you and placed at %s. ' \
        'You can now use this key to log into any of the machines you ' \
        'specified without providing a password via the following ' \
        'command:\n    ssh root@%s -i %s' % (pvt_key, head_node.id, pvt_key))

def run_instances(options):
  """
  Start a new AppScale PaaS instance over a given infrastructure.

  Args:
    options An instance of RunInstancesOptions class

  Raises:
    AppScaleToolsException  If an error occurs while starting the AppScale
                            instance.
  """
  logger = commons.get_logger(options.verbose)

  # Validate and verify the input parameters
  node_layout, app_info = options.validate()
  app_name = app_info[0]
  if options.infrastructure:
    logger.info('Starting AppScale over %s' % options.infrastructure)
  else:
    logger.info('Starting AppScale in a non-cloud environment')

  # Generate a secret key for the AppScale instance
  secret_key = commons.generate_secret_key(__get_secret_key_file(
    options.keyname))

  # Start the head node of the AppScale instance
  head_node, instance_info, locations = __spawn_head_node(options, node_layout)

  # Find a SSH key that can be used to login to the head node
  ssh_key = __find_ssh_key(head_node.id, options.keyname, options.infrastructure)

  # Start the AppController (Djinn) on the head node
  __start_app_controller(head_node.id, options, ssh_key)
  logger.info('Head node successfully initialized at %s' % head_node.id)

  # Pass the required parameters to the AppController on the head node
  client = AppControllerClient(head_node.id, secret_key)
  while not client.is_port_open():
    sleep(2)
  credentials = __generate_appscale_credentials(options, node_layout,
    head_node.id, ssh_key)
  if logger.is_verbose:
    logger.verbose('Setting AppScale credentials: ' + str(credentials))
    logger.verbose('Setting locations parameter to: ' + str(locations))
  client.set_parameters(locations, commons.map_to_array(credentials), app_name)

  # Create admin user accounts and setup permissions
  login_host, username = __setup_admin_login(options, secret_key, client)

  # Wait for all other AppScale nodes to come up.
  # At this point the user app server is up and running which
  # means all the other nodes should also be up and running.
  # Therefore call to get_all_public_ips() must return the full
  # list of IPs.
  public_ips = client.get_all_public_ips()
  __wait_for_all_nodes(public_ips, secret_key)

  # Save the status of this AppScale instance in the local file system
  # for future reference (eg: for termination)
  node_info = {
    ':load_balancer' : head_node.id,
    ':instance_id' : instance_info[2],
    ':table' : options.database,
    ':shadow' : head_node.id,
    ':secret' : secret_key,
    ':db_master' : node_layout.get_db_master().id,
    ':infrastructure' : options.infrastructure,
    ':group' : options.group,
    ':ips' : public_ips
  }
  __write_node_file(node_info, options.keyname, head_node.id, ssh_key)

  # Upload and deploy the applications in the AppScale cloud
  if app_name is None:
    logger.info('No application was specified for deployment. You can later '
                'upload an application using the appscale-upload-app command')
  else:
    __deploy_application(login_host, client, app_info, username, ssh_key)

  # And we are ready to rock and roll...
  logger.info('The status of your AppScale instance can be found at '
              'http://%s/status' % login_host)

def __deploy_application(login_host, client, app_info, username, ssh_key):
  logger = commons.get_logger()
  app_name, app_file, language = app_info[0], app_info[1], app_info[2]
  user_manager = UserManagementClient(login_host, client.secret)
  user_manager.reserve_application_name(username, app_name, language)
  logger.info('Application name %s has been reserved' % app_name)

  app_dir = "/var/apps/%s/app" % app_name
  remote_file_path = "%s/%s.tar.gz" % (app_dir, app_name)
  make_app_dir = "mkdir -p %s" % app_dir
  logger.info('Creating remote directory to copy app into')
  commons.run_remote_command(make_app_dir, client.host, ssh_key)
  logger.info('Copying over app')
  commons.scp_file(app_file, remote_file_path, client.host, ssh_key)
  client.commit_application(app_name, remote_file_path)
  while not client.is_app_running(app_name):
    logger.info('Waiting for application %s to start...' % app_name)
    sleep(10)
  app_url = 'http://%s/apps/%s' % (client.host, app_name)
  logger.info('Your app can be reached at %s' % app_url)
  if app_file.startswith('/tmp'):
    shutil.rmtree(os.path.dirname(app_file))

def __get_appscale_dir():
  """
  Returns the absolute path to the local AppScale metadata directory.
  If this directory does not exist in the local file system, this
  method will create it before returning the path to it.

  Returns:
    Absolute path to the AppScale metadata directory
  """
  appscale_dir = os.path.expanduser(APPSCALE_DIR)
  if not os.path.exists(appscale_dir):
    os.mkdir(appscale_dir)
  return appscale_dir

def __wait_for_all_nodes(all_ips, secret_key):
  logger = commons.get_logger()
  while True:
    all_up = True
    for ip in all_ips:
      temp_client = AppControllerClient(ip, secret_key)
      if not temp_client.is_initialized():
        logger.info('Waiting for node %s to fully initialize...' % ip)
        all_up = False
        break
    if all_up:
      break
    else:
      sleep(5)

def __spawn_head_node(options, node_layout):
  logger = commons.get_logger()
  if cloud.is_valid_cloud_type(options.infrastructure):
    cloud.configure_security(options.infrastructure, options.keyname,
      options.group, __get_appscale_dir())
    instance_info = cloud.spawn_head_node(options.infrastructure,
      options.keyname, options.group, options.machine, options.instance_type)
    head_node = node_layout.get_head_node()
    head_node.id = instance_info[0]
    logger.info('Head node booted up with IP: %s' % head_node.id)
  else:
    logger.verbose('Deploying AppScale on a non-cloud environment')
    head_node = node_layout.get_head_node()
    instance_info = (head_node.id, head_node.id, 'virtual_node')

  head_node_roles = ':'.join(head_node.roles)
  location = instance_info[0] + ':' + instance_info[1] + \
             ':' + head_node_roles + ':' + instance_info[2]
  if logger.is_verbose:
    logger.verbose('Head node available at %s' % instance_info[0])
    logger.verbose('Head node private IP: %s' % instance_info[1])
    logger.verbose('Head node instance ID: %s' % instance_info[2])
    logger.verbose('Head node roles: %s' % head_node_roles)
  return head_node, instance_info, [ location ]

def __generate_appscale_credentials(options, node_layout, node, ssh_key):
  ips_dict = node_layout.to_dictionary()
  ips_to_use = ''
  for k,v in ips_dict.items():
    if len(ips_to_use) > 0:
      ips_to_use += '..'
    ips_to_use += k + '--' + v

  credentials = {
    'table' : options.database,
    'hostname' : node,
    'keyname' : options.keyname,
    'keypath' : ssh_key,
    'replication' : node_layout.replication,
    'appengine' : options.app_engines,
    'autoscale' : options.auto_scale,
    'group' : options.group,
    'ips' : ips_to_use
  }

  if options.database == 'voldemort':
    credentials['voldemortr'] = node_layout.read_factor
    credentials['voldemortw'] = node_layout.write_factor
  elif options.database == 'simpledb':
    credentials['SIMPLEDB_ACCESS_KEY'] = os.environ['SIMPLEDB_ACCESS_KEY']
    credentials['SIMPLEDB_SECRET_KEY'] = os.environ['SIMPLEDB_SECRET_KEY']

  if cloud.is_valid_cloud_type(options.infrastructure):
    credentials['infrastructure'] = options.infrastructure
    credentials['machine'] = options.machine
    credentials['instance_type'] = options.instance_type
    credentials['min_images'] = node_layout.min_images
    credentials['max_images'] = node_layout.max_images
    cloud_credentials = cloud.get_cloud_env_variables(options.infrastructure)
    for key, value in cloud_credentials.items():
      credentials[key] = value

  if options.restore_from_tar:
    db_backup = '/root/db-backup.tar.gz'
    credentials['restore_from_tar'] = db_backup
    commons.scp_file(options.restore_from_tar, db_backup, node, ssh_key)

  if options.restore_neptune_info:
    neptune_info = '/etc/appscale/neptune_info.txt'
    commons.scp_file(options.restore_neptune_info, neptune_info, node, ssh_key)
  return credentials

def __start_app_controller(node, options, ssh_key):
  logger = commons.get_logger()
  location = '/etc/appscale'
  if not commons.remote_location_exists(location, node, ssh_key):
    commons.error('Failed to locate an AppScale installation in the remote '
                  'instance at %s' % node)

  location = '/etc/appscale/%s' % VERSION
  if not commons.remote_location_exists(location, node, ssh_key):
    commons.error('AppScale version installed at %s is not compatible with '
                  'your version of tools' % node)

  location = '/etc/appscale/%s/%s' % (VERSION, options.database)
  if not commons.remote_location_exists(location, node, ssh_key):
    commons.error('AppScale version installed at %s does not have support '
                  'for %s' % (node, options.database))

  if options.scp is not None:
    commons.copy_appscale_source(options.scp, node, ssh_key)

  remote_key_file = '/root/.appscale/%s.key' % options.keyname
  commons.scp_file(ssh_key, remote_key_file, node, ssh_key)

  secret_key_file = __get_secret_key_file(options.keyname)
  commons.scp_file(secret_key_file, '/etc/appscale/secret.key', node, ssh_key)

  commons.scp_file(ssh_key, '/etc/appscale/ssh.key', node, ssh_key)

  if cloud.is_valid_cloud_type(options.infrastructure):
    logger.info('Copying over credentials for cloud')
    remote_dir = '/etc/appscale/keys/cloud1'
    commons.run_remote_command('mkdir -p %s' % remote_dir, node, ssh_key)
    cloud_pk, cloud_cert = cloud.get_security_keys(options.infrastructure)
    commons.scp_file(ssh_key, '%s/%s' % (remote_dir,os.path.basename(ssh_key)),
      node, ssh_key)
    commons.scp_file(cloud_pk, '%s/mykey.pem' % remote_dir, node, ssh_key)
    commons.scp_file(cloud_cert, '%s/mycert.pem' % remote_dir, node, ssh_key)

  logger.info('Generating a key-pair for this instance of AppScale PaaS')
  pk, cert = commons.generate_certificate(__get_appscale_dir(), options.keyname)
  commons.scp_file(pk, '/etc/appscale/certs/mykey.pem', node, ssh_key)
  commons.scp_file(cert, '/etc/appscale/certs/mycert.pem', node, ssh_key)

  logger.info('Starting AppController on the head node: %s' % node)
  god_file = '/tmp/controller.god'
  commons.scp_file('utils/resources/controller.god', god_file, node, ssh_key)
  commons.run_remote_command('god &', node, ssh_key)
  commons.run_remote_command('god load ' + god_file, node, ssh_key)
  commons.run_remote_command('god start controller', node, ssh_key)

def __get_secret_key_file(keyname):
  return os.path.join(__get_appscale_dir(), keyname + '.secret')

def __find_ssh_key(host, keyname, infrastructure=None):
  logger = commons.get_logger()
  appscale_dir = __get_appscale_dir()
  named_key_loc = os.path.join(appscale_dir, keyname + '.key')
  named_backup_key_loc = os.path.join(appscale_dir, keyname + '.private')

  if infrastructure:
    while True:
      logger.verbose('Checking if SSH daemon is running on head node')
      port_open = commons.is_port_open(host, 22)
      if port_open:
        break
      else:
        logger.info('Waiting for head node to finish boot up process...')
        sleep(10)
    logger.verbose('Enabling root login on the head node')
    command = 'sudo cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/'
    commons.run_remote_command(command, host, named_key_loc, user='ubuntu')
    commons.scp_file(named_key_loc, '/root/.ssh/id_rsa', host, named_key_loc)

  ssh_key = None
  key_exists = False
  for key in (named_key_loc, named_backup_key_loc):
    if os.path.exists(key):
      key_exists = True
      if commons.is_ssh_key_valid(key, host):
        ssh_key = key
        break
  if not key_exists:
    commons.error('Unable to find a SSH key to login to AppScale nodes')
  elif ssh_key is None:
    commons.error('Unable to login to AppScale nodes with available SSH keys')
  return ssh_key

def __setup_admin_login(options, secret_key, client):
  logger = commons.get_logger()
  if options.username is None and options.password is None:
    if options.testing:
      username = os.environ['APPSCALE_USERNAME'] if os.environ.has_key(
        'APPSCALE_USERNAME') else 'a@a.a'
      password = os.environ['APPSCALE_PASSWORD'] if os.environ.has_key(
        'APPSCALE_PASSWORD') else 'aaaaaa'
    else:
      logger.info('This AppScale instance is linked to an e-mail address '
                  'giving it administrator privileges')
      username, password = commons.prompt_for_user_credentials()
  else:
    logger.info('Using the provided username and password')
    username = options.username
    password = options.password

  um_host = client.get_user_manager_host()
  login_host = client.get_login_host()
  user_manager = UserManagementClient(um_host, secret_key)
  while not user_manager.is_port_open():
    logger.info('Waiting for user manager service...')
    sleep(10)
  user_manager.create_user(username, password)
  logger.info('Created user account for: %s' % username)

  xmpp_user = username[:username.index('@')] + '@' + login_host
  user_manager.create_user(xmpp_user, password)
  logger.info('Created XMPP user account for: %s' % xmpp_user)

  user_manager.set_admin_role(username)
  logger.info('Admin privileges granted to: %s' % username)
  return login_host, username

def __write_node_file(node_info, keyname, host, ssh_key):
  node_file_path = os.path.join(__get_appscale_dir(),
    'locations-%s.yaml' % keyname)
  node_file = open(node_file_path, 'w')
  yaml.dump(node_info, node_file, default_flow_style=False)
  node_file.close()
  remote_node_file = '/root/.appscale/locations-%s.yaml' % keyname
  commons.scp_file(node_file_path, remote_node_file, host, ssh_key)
