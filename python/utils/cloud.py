from datetime import datetime
import os
import shutil
import boto
import time
from boto.exception import EC2ResponseError
from utils import commons
from utils.commons import AppScaleToolsException

__author__ = 'hiranya'

class CloudAgent:
  def spawn_vms(self, count, key_name, group_name, machine, instance_type):
    raise NotImplemented

  def configure_security(self, key_name, group_name, path):
    raise NotImplemented

  def describe_instances(self, keyname):
    raise NotImplemented

  def validate(self, machine):
    raise NotImplemented

  def get_environment_variables(self):
    raise NotImplemented

class EC2Agent(CloudAgent):
  def __init__(self):
    self.image_id_prefix = 'ami-'
    self.required_variables = [
      "EC2_PRIVATE_KEY", "EC2_CERT", "EC2_SECRET_KEY", "EC2_ACCESS_KEY"
    ]

  def configure_security(self, key_name, group_name, path):
    try:
      conn = self.open_connection()

      reservations = conn.get_all_instances()
      instances = [i for r in reservations for i in r.instances]
      for i in instances:
        if i.state == 'running' and i.key_name == key_name:
          raise AppScaleToolsException('Specified key name is already in use.')

      key = conn.get_key_pair(key_name)
      named_key_loc = os.path.join(path, key_name + '.key')
      named_backup_key_loc = os.path.join(path, key_name + '.private')
      if key is None:
        key = conn.create_key_pair(key_name)
        for loc in (named_key_loc, named_backup_key_loc):
          key_file = open(loc, 'w')
          key_file.write(key.material)
          key_file.close()
      elif os.path.exists(named_key_loc) and \
           not os.path.exists(named_backup_key_loc):
        shutil.copy(named_key_loc, named_backup_key_loc)
      elif not os.path.exists(named_key_loc) and \
           os.path.exists(named_backup_key_loc):
        shutil.copy(named_backup_key_loc, named_key_loc)
      elif not os.path.exists(named_key_loc) and \
           not os.path.exists(named_backup_key_loc):
        msg = 'Specified key: %s already exists in the cloud but a copy of it' \
              'cannot be found in the local file system.' % key_name
        raise AppScaleToolsException(msg)

      os.chmod(named_key_loc, 0600)
      os.chmod(named_backup_key_loc, 0600)

      groups = conn.get_all_security_groups()
      group_exists = False
      for group in groups:
        if group.name == group_name:
          group_exists = True
          break
      if not group_exists:
        conn.create_security_group(group_name, 'AppScale security group')
        conn.authorize_security_group(group_name, from_port=1,
          to_port=65535, ip_protocol='udp')
        conn.authorize_security_group(group_name, from_port=1,
          to_port=65535, ip_protocol='tcp')
        conn.authorize_security_group(group_name, ip_protocol='icmp',
          cidr_ip='0.0.0.0/0')
    except Exception as e:
      self.handle_exception('Error while configuring cloud security', e)

  def spawn_vms(self, count, key_name, group_name, machine, instance_type):
    try:
      conn = self.open_connection()

      instance_info = self.describe_instances(key_name)
      conn.run_instances(machine, count, count, key_name=key_name,
        security_groups=[group_name], instance_type=instance_type)

      end_time = datetime.datetime.now() + datetime.timedelta(0, 1800)
      now = datetime.datetime.now()

      while now < end_time:
        time_left = (end_time - now).seconds
        print('[{0}] {1} seconds left...'.format(now, time_left))
        latest_instance_info = self.describe_instances(key_name)
        public_ips = commons.diff(latest_instance_info[0], instance_info[0])
        if count == len(public_ips):
          private_ips = []
          instance_ids = []
          for public_ip in public_ips:
            index = latest_instance_info[0].index(public_ip)
            private_ips.append(latest_instance_info[1][index])
            instance_ids.append(latest_instance_info[2][index])
          return public_ips, private_ips, instance_ids
        time.sleep(20)
        now = datetime.datetime.now()
    except Exception as e:
      self.handle_exception('Error while starting VMs in the cloud', e)

    raise AppScaleToolsException('Failed to spawn the required VMs')

  def handle_exception(self, msg, exception):
    if isinstance(exception, EC2ResponseError):
      raise AppScaleToolsException(msg + ': ' + exception.error_message)
    else:
      raise AppScaleToolsException(msg + ': ' + exception.message)

  def describe_instances(self, keyname):
    instance_ids = []
    public_ips = []
    private_ips = []

    conn = self.open_connection()
    reservations = conn.get_all_instances()
    instances = [i for r in reservations for i in r.instances]
    for i in instances:
      if i.state == 'running' and i.key_name == keyname:
        instance_ids.append(i.id)
        public_ips.append(i.public_dns_name)
        private_ips.append(i.private_dns_name)
    return public_ips, private_ips, instance_ids

  def validate(self, machine):
    if machine is None:
      raise AppScaleToolsException('Machine image ID not specified')
    elif not machine.startswith(self.image_id_prefix):
      raise AppScaleToolsException('Invalid machine image ID: ' + machine)

    for var in self.required_variables:
      if os.environ.get(var) is None:
        msg = 'Required environment variable: %s not set' % var
        raise AppScaleToolsException(msg)

    conn = self.open_connection()
    image = conn.get_image(machine)
    if image is None:
      raise AppScaleToolsException('Machine image %s does not exist' % machine)

  def get_environment_variables(self):
    values = {}
    for var in self.required_variables:
      values['CLOUD_' + var] = os.environ.get(var)

    return values

  def open_connection(self):
    access_key = os.environ['EC2_ACCESS_KEY']
    secret_key = os.environ['EC2_SECRET_KEY']
    return boto.connect_ec2(access_key, secret_key)

class EucaAgent(EC2Agent):
  pass

CLOUD_AGENTS = {
  'ec2' : EC2Agent(),
  'euca' : EucaAgent()
}

def validate(infrastructure, machine):
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  cloud_agent.validate(machine)

def get_cloud_env_variables(infrastructure):
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  return cloud_agent.get_environment_variables()

def spawn_head_node(infrastructure, key_name, group_name, machine, instance_type):
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  return cloud_agent.spawn_vms(1, key_name, group_name, machine, instance_type)

def configure_security(infrastructure, key_name, group_name, path):
  cloud_agent = CLOUD_AGENTS.get(infrastructure)
  return cloud_agent.configure_security(key_name, group_name, path)

def is_valid_cloud_type(type):
  return type is not None and CLOUD_AGENTS.has_key(type)