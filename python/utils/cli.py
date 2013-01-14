import optparse

__author__ = 'hiranya'

OPTION_APP_FILE = 'file'
OPTION_APPENGINE = 'appengine'
OPTION_AUTO = 'auto'
OPTION_AUTO_SCALE = 'autoscale'
OPTION_DATABASE = 'database'
OPTION_GROUP = 'group'
OPTION_INFRASTRUCTURE = 'infrastructure'
OPTION_INSTANCE_TYPE = 'instance_type'
OPTION_IPS = 'ips'
OPTION_KEYNAME = 'keyname'
OPTION_MACHINE = 'machine'
OPTION_MAX_IMAGES = 'max'
OPTION_MIN_IMAGES = 'min'
OPTION_READ_FACTOR = 'read_factor'
OPTION_REPLICATION = 'replication'
OPTION_RESTORE_FROM_TAR = 'restore_from_tar'
OPTION_RESTORE_NEPTUNE_INFO = 'restore_neptune_info'
OPTION_SCP = 'scp'
OPTION_WRITE_FACTOR = 'write_factor'

class CLIOption:
  TYPE_BOOL = 'bool'
  TYPE_INT = 'int'
  TYPE_STRING = 'string'
  TYPE_CHOICES = 'choices'

  def __init__(self, name, description, type=TYPE_STRING,
               default=None, choices=None):
    self.name = name
    self.description = description
    self.type = type
    self.default = default
    self.choices = choices

class CLIOptionRepo:
  REPO = { }

  def __init__(self):
    self.put(OPTION_APP_FILE,
      'Application file to upload and deploy in the AppScale cloud')
    self.put(OPTION_APPENGINE,
      'Number of appengine servers that should be spawned to host each application',
      type=CLIOption.TYPE_INT)
    self.put(OPTION_AUTO,
      'Automatically respond to all the prompts and warnings',
      type=CLIOption.TYPE_BOOL, default=False)
    self.put(OPTION_AUTO_SCALE,
      'Automatically scale up and down to handle varying loads',
      type=CLIOption.TYPE_BOOL, default=False)
    self.put(OPTION_DATABASE,
      'Database engine to use with AppScale',
      type=CLIOption.TYPE_CHOICES,
      choices=[ 'cassandra', 'hbase', 'mysql' ],
      default='cassandra')
    self.put(OPTION_GROUP,
      'Name of the security group to use when running over an IaaS layer (defaults to "appscale")',
      default='appscale')
    self.put(OPTION_INFRASTRUCTURE,
      'The cloud infrastructure to deploy AppScale on',
      type=CLIOption.TYPE_CHOICES,
      choices=[ 'ec2', 'euca' ])
    self.put(OPTION_INSTANCE_TYPE,
      'Type of cloud VMs to spawn',
      type=CLIOption.TYPE_CHOICES,
      choices=[ 'm1.large', 'c1.xlarge' ],
      default='m1.large')
    self.put(OPTION_IPS,
      'Path to the yaml file that contains the IP addresses of nodes')
    self.put(OPTION_KEYNAME,
      'Key name of the target AppScale deployment (defaults to "appscale")',
      default='appscale')
    self.put(OPTION_MACHINE,
      'Machine image to use when spawning VMs in the cloud')
    self.put(OPTION_MAX_IMAGES,
      'Maximum number of VMs to spawn',
      type=CLIOption.TYPE_INT)
    self.put(OPTION_MIN_IMAGES,
      'Minimum number of VMs to spawn',
      type=CLIOption.TYPE_INT)
    self.put(OPTION_READ_FACTOR,
      'The number of database nodes that should take part in read quorums',
      type=CLIOption.TYPE_INT)
    self.put(OPTION_REPLICATION,
      'The replication factor for the underlying database',
      type=CLIOption.TYPE_INT)
    self.put(OPTION_RESTORE_FROM_TAR,
      'Path to a tarball containing a previous AppScale deployment from which to restore the state')
    self.put(OPTION_RESTORE_NEPTUNE_INFO,
      'Path to a Neptune job metadata file from which to restore the state')
    self.put(OPTION_SCP,
      'Path to an AppScale source tree which will be copied to and deployed in the target AppScale cloud')
    self.put(OPTION_WRITE_FACTOR,
      'The number of database nodes that should take part in write quorums',
      type=CLIOption.TYPE_INT)

  def put(self, name, description, type=CLIOption.TYPE_STRING,
          default=None, choices=None):
    self.REPO[name] = CLIOption(name, description, type, default, choices)

  def get(self, name):
    return self.REPO[name]

def get_parser(options):
  parser = optparse.OptionParser()
  repo = CLIOptionRepo()
  for option in options:
    cli_option = repo.get(option)
    if cli_option.type == CLIOption.TYPE_BOOL:
      parser.add_option('--' + cli_option.name,
        action='store_true',
        dest=cli_option.name,
        help=cli_option.description)
    elif cli_option.type == CLIOption.TYPE_INT:
      parser.add_option('--' + cli_option.name,
        action='store',
        type='int',
        dest=cli_option.name,
        help=cli_option.description)
    elif cli_option.type == CLIOption.TYPE_CHOICES:
      parser.add_option('--' + cli_option.name,
        action='store',
        choices=cli_option.choices,
        dest=cli_option.name,
        help=cli_option.description)
    else:
      parser.add_option('--' + cli_option.name,
        action='store',
        type='string',
        dest=cli_option.name,
        help=cli_option.description)

    if cli_option.default is not None:
      parser.set_default(cli_option.name, cli_option.default)
  return parser

def print_usage_and_exit(msg, parser):
  print msg
  print
  parser.print_help()
  exit(1)


