import getpass
import os
from utils import commons, cli, cloud
from utils.app_controller_client import AppControllerClient
from utils.commons import AppScaleToolsException
from utils.node_layout import NodeLayout

__author__ = 'hiranya'

APPSCALE_DIR = '~/.appscale'

class AddKeyPairOptions:
  def __init__(self, ips, keyname, auto=False):
    self.ips = ips
    self.keyname = keyname
    self.auto = auto
    self.root_password = None

class RunInstancesOptions:
  def __init__(self):
    self.infrastructure = None
    self.machine = None
    self.instance_type = None
    self.ips = None
    self.database = None
    self.min = None
    self.max = None
    self.keyname = None
    self.group = None
    self.scp = None
    self.file = None
    self.replication = None
    self.read_q = None
    self.write_q = None
    self.app_engines = None
    self.auto_scale = None
    self.restore_from_tar = None
    self.restore_neptune_info = None

def add_key_pair(options):
  node_layout = NodeLayout(options.ips)

  required_commands = [ 'ssh-keygen', 'ssh-copy-id' ]
  if options.auto:
    required_commands.append('expect')
  commons.assert_commands_exist(required_commands)

  appscale_dir = os.path.expanduser(APPSCALE_DIR)
  if not os.path.exists(appscale_dir):
    os.mkdir(appscale_dir)
  key_info = commons.generate_rsa_key(appscale_dir, options.keyname)
  pvt_key = key_info[0]
  public_key = key_info[1]

  if options.auto and options.root_password is None:
    options.root_password = getpass.getpass('Enter SSH password of root: ')

  for node in node_layout.nodes:
    commons.ssh_copy_id(node.id, pvt_key, options.auto,
      'sshcopyid', options.root_password)

  head_node = node_layout.get_head_node()
  commons.scp_file(pvt_key, '~/.ssh/id_dsa', head_node.ip, pvt_key)
  commons.scp_file(public_key, '~/.ssh/id_rsa.pub', head_node.ip, pvt_key)

  print 'A new ssh key has been generated for you and placed at %s. ' \
        'You can now use this key to log into any of the machines you ' \
        'specified without providing a password via the following ' \
        'command:\n    ssh root@%s -i %s' % (pvt_key, head_node.id, pvt_key)

def run_instances(options):
  layout_options = {
    cli.OPTION_INFRASTRUCTURE : options.infrastructure,
    cli.OPTION_DATABASE : options.database,
    cli.OPTION_MIN_IMAGES : options.min,
    cli.OPTION_MAX_IMAGES : options.max,
    cli.OPTION_REPLICATION : options.replication,
    cli.OPTION_READ_FACTOR : options.read_q,
    cli.OPTION_WRITE_FACTOR : options.write_q
  }
  node_layout = NodeLayout(options.ips, layout_options)

  if options.file is not None:
    app_info = commons.get_app_info(options.file, options.database)
  else:
    app_info = ( 'none' )

  appscale_dir = os.path.expanduser(APPSCALE_DIR)
  if not os.path.exists(appscale_dir):
    os.mkdir(appscale_dir)

  if options.infrastructure:
    cloud.validate(options.infrastructure, options.machine)
    print 'Starting AppScale over', options.infrastructure
  else:
    print 'Starting AppScale in a non-cloud environment'

  secret_key_file = os.path.join(APPSCALE_DIR, options.keyname + '.secret')
  secret_key = commons.generate_secret_key(secret_key_file)

  if cloud.is_valid_cloud_type(options.infrastructure):
    cloud.configure_security(options.infrastructure, options.keyname,
      options.group, appscale_dir)
    instance_info = cloud.spawn_head_node(options.infrastructure, options.keyname,
      options.group, options.machine, options.instance_type)
    head_node = instance_info[0][0]
  else:
    head_node = node_layout.get_head_node()
    instance_info = ([head_node.id], [head_node.id], ['virtual_node'])

  locations = []
  for i in range(len(instance_info[0])):
    location = instance_info[0][i] + ':' + instance_info[1][i] + \
               ':' + instance_info[2][i]
    locations.append(location)

  named_key_loc = os.path.join(appscale_dir, options.keyname + '.key')
  named_backup_key_loc = os.path.join(appscale_dir, options.keyname + '.private')
  ssh_key = None
  key_exists = False
  for key in (named_key_loc, named_backup_key_loc):
    if os.path.exists(key):
      key_exists = True
      if commons.is_ssh_key_valid(key, head_node.id):
        ssh_key = key
        break

  if not key_exists:
    msg = 'Unable to find a SSH key to login to AppScale nodes'
    raise AppScaleToolsException(msg)
  elif ssh_key is None:
    msg = 'Unable to login to AppScale nodes with the available SSH keys'
    raise AppScaleToolsException(msg)

  # TODO: Ensure image is AppScale

  if options.scp is not None:
    commons.copy_appscale_source(options.scp, head_node.id, ssh_key)

  remote_key_file = '/root/.appscale/%s.key' % options.keyname
  commons.scp_file(ssh_key, remote_key_file, head_node.id, ssh_key)

  credentials = {
    'table' : options.database,
    'hostname' : head_node.id,
    'keyname' : options.keyname,
    'keypath' : ssh_key,
    'replication' : node_layout.replication,
    'appengine' : options.app_engines,
    'autoscale' : options.auto_scale,
    'group' : options.group
  }
  if options.database == 'voldemort':
    credentials['voldemortr'] = node_layout.read_factor
    credentials['voldemortw'] = node_layout.write_factor
  elif options.database == 'simpledb':
    credentials['SIMPLEDB_ACCESS_KEY'] = os.environ['SIMPLEDB_ACCESS_KEY']
    credentials['SIMPLEDB_SECRET_KEY'] = os.environ['SIMPLEDB_SECRET_KEY']

  if cloud.is_valid_cloud_type(options.infrastructure):
    cloud_credentials = cloud.get_cloud_env_variables(options.infrastructure)
    for key, value in cloud_credentials.items():
      credentials[key] = value

  if options.restore_from_tar:
    db_backup = '/root/db-backup.tar.gz'
    credentials['restore_from_tar'] = db_backup
    commons.scp_file(options.restore_from_tar, db_backup, head_node.id, ssh_key)

  if options.restore_neptune_info:
    neptune_info = '/etc/appscale/neptune_info.txt'
    commons.scp_file(options.restore_neptune_info, neptune_info,
      head_node.id, ssh_key)

  print 'Head node successfully initialized at', head_node.id

  # TODO: copy keys

  god_file = '/tmp/controller.god'
  commons.scp_file('resources/controller.god', god_file, head_node.id, ssh_key)
  commons.run_remote_command('god load ' + god_file, head_node.id, ssh_key)
  commons.run_remote_command('god start controller', head_node.id, ssh_key)

  client = AppControllerClient(head_node.id, secret_key)
  client.set_parameters(locations, credentials, app_info[0])

