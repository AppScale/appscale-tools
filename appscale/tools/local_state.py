#!/usr/bin/env python
# Programmer: Chris Bunch, Brian Drawert


# First-party Python imports
import getpass
import hashlib
import json
import locale
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import yaml


# AppScale-specific imports
from appcontroller_client import AppControllerClient
from appscale_logger import AppScaleLogger
from custom_exceptions import AppScaleException
from custom_exceptions import AppScalefileException
from custom_exceptions import BadConfigurationException
from custom_exceptions import ShellException


# The version of the AppScale Tools we're running on.
APPSCALE_VERSION = "2.8.0"


class LocalState(object):
  """LocalState handles all interactions necessary to read and write AppScale
  configuration files on the machine that executes the AppScale Tools.
  """


  # The number of times to execute shell commands before aborting, by default.
  DEFAULT_NUM_RETRIES = 5


  # The path on the local filesystem where we can read and write
  # AppScale deployment metadata.
  LOCAL_APPSCALE_PATH = os.path.expanduser("~") + os.sep + ".appscale" + os.sep


  # The path on the local filesystem where we can find the keyname file.
  ETC_APPSCALE_KEY_PATH = "/etc/appscale/keys/cloud1/"


  # A list of valid paths on the local filesystem where we could find the
  # keyname file.
  VALID_KEY_PATHS = [LOCAL_APPSCALE_PATH, ETC_APPSCALE_KEY_PATH]


  # The length of the randomly generated secret that is used to authenticate
  # AppScale services.
  SECRET_KEY_LENGTH = 32


  # The username for the cloud administrator if the --test options is used.
  DEFAULT_USER = "a@a.com"


  # The password to set for the default user.
  DEFAULT_PASSWORD = "aaaaaa"


  @classmethod
  def make_appscale_directory(cls):
    """Creates a ~/.appscale directory, if it doesn't already exist.
    """
    if os.path.exists(cls.LOCAL_APPSCALE_PATH):
      return
    else:
      os.mkdir(cls.LOCAL_APPSCALE_PATH)


  @classmethod
  def ensure_appscale_isnt_running(cls, keyname, force):
    """Checks the secret key file to see if AppScale is running, and
    aborts if it is.

    Args:
      keyname: The keypair name that is used to identify AppScale deployments.
      force: A bool that is used to run AppScale even if the secret key file
        is present.
    Raises:
      BadConfigurationException: If AppScale is already running.
    """
    if force:
      return

    if os.path.exists(cls.get_secret_key_location(keyname)):
      raise BadConfigurationException("AppScale is already running. Terminate" +
        " it, set 'force: True' in your AppScalefile, or use the --force flag" +
        " to run anyways.")


  @classmethod
  def generate_secret_key(cls, keyname):
    """Creates a new secret, which is used to authenticate callers that
    communicate between services in an AppScale deployment.

    Args:
      keyname: A str representing the SSH keypair name used for this AppScale
        deployment.
    Returns:
      A str that represents the secret key.
    """
    key = str(uuid.uuid4()).replace('-', '')[:cls.SECRET_KEY_LENGTH]
    with open(cls.get_secret_key_location(keyname), 'w') as file_handle:
      file_handle.write(key)
    return key


  @classmethod
  def get_secret_key_location(cls, keyname):
    """Returns the path on the local filesystem where the secret key can be
    located.

    Args:
      keyname: A str representing the SSH keypair name used for this AppScale
        deployment.
    Returns:
      A str that corresponds to a location on the local filesystem where the
      secret key can be found.
    """
    return cls.LOCAL_APPSCALE_PATH + keyname + ".secret"


  @classmethod
  def get_secret_key(cls, keyname):
    """Retrieves the secret key, used to authenticate AppScale services.

    Args:
      keyname: A str representing the SSH keypair name used for this AppScale
        deployment.
    Returns:
      A str containing the secret key.
    """
    with open(cls.get_secret_key_location(keyname), 'r') as file_handle:
      return file_handle.read()


  @classmethod
  def write_key_file(cls, location, contents):
    """Writes the SSH key contents to the given location and makes it
    usable for SSH connections.

    Args:
      location: A str representing the path on the local filesystem where the
        SSH key should be written to.
      contents: A str containing the SSH key.
    """
    with open(location, 'w') as file_handle:
      file_handle.write(contents)
    os.chmod(location, 0600)  # so that SSH will accept the key


  @classmethod
  def generate_deployment_params(cls, options, node_layout, first_host,
    additional_creds):
    """Constructs a dict that tells the AppController which machines are part of
    this AppScale deployment, what their roles are, and how to host API services
    within this deployment.

    Args:
      options: A Namespace that dictates API service information, not including
        information about machine to role hosting.
      node_layout: A NodeLayout that indicates which machines host which roles
        (API services).
      first_host: A str that indicates which machine should be contacted by
        others to bootstrap and get initial service information.
      additional_creds: A dict that specifies arbitrary credentials that should
        also be passed in with the generated parameters.
    Returns:
      A dict whose keys indicate API service information as well as a special
      key that indicates machine to role mapping information.
    """
    creds = {
      "table" : options.table,
      "hostname" : first_host,
      "ips" : json.dumps(node_layout.to_list_without_head_node()),
      "keyname" : options.keyname,
      "replication" : str(node_layout.replication_factor()),
      "appengine" : str(options.appengine),
      "autoscale" : str(options.autoscale),
      "alter_etc_resolv" : str(options.alter_etc_resolv),
      "clear_datastore" : str(options.clear_datastore),
      "user_commands" : json.dumps(options.user_commands),
      "verbose" : str(options.verbose),
      "flower_password" : options.flower_password,
      "max_memory" : options.max_memory
    }
    creds.update(additional_creds)

    if options.infrastructure:
      iaas_creds = {
        'machine' : options.machine,
        'infrastructure' : options.infrastructure,
        'group' : options.group,
        'min_images' : node_layout.min_vms,
        'max_images' : node_layout.max_vms,
        'use_spot_instances' : options.use_spot_instances,
        'zone' : json.dumps(options.zone)
      }

      if options.infrastructure in ["ec2", "euca"]:
        iaas_creds['instance_type'] = options.instance_type
      elif options.infrastructure == "gce":
        iaas_creds['project'] = options.project
        iaas_creds['gce_user'] = getpass.getuser()
        iaas_creds['instance_type'] = options.gce_instance_type

      creds.update(iaas_creds)

    return creds


  @classmethod
  def obscure_dict(cls, dict_to_obscure):
    """Creates a copy of the given dictionary, but replaces values that may be
    too sensitive to print to standard out or log with a partially masked
    version.

    Args:
      dict_to_obscure: The dictionary whose values we wish to obscure.
    Returns:
      A dictionary with the same keys as dict_to_obscure, but with values that
      are masked if the key relates to a cloud credential.
    """
    obscured = {}
    obscure_regex = re.compile('(.*EC2.*)|(.*ec2.*)')
    for key, value in dict_to_obscure.iteritems():
      if obscure_regex.match(key):
        obscured[key] = cls.obscure_str(value)
      else:
        obscured[key] = value

    return obscured


  @classmethod
  def obscure_str(cls, str_to_obscure):
    """Obscures the given string by replacing all but four of its characters
    with asterisks.

    Args:
      str_to_obscure: The str that we wish to obscure.
    Returns:
      A str whose contents have been replaced by asterisks, except for the
      trailing 4 characters.
    """
    if len(str_to_obscure) < 4:
      return str_to_obscure
    last_four = str_to_obscure[len(str_to_obscure)-4:len(str_to_obscure)]
    return "*" * (len(str_to_obscure) - 4) + last_four


  @classmethod
  def generate_ssl_cert(cls, keyname, is_verbose):
    """Generates a self-signed SSL certificate that AppScale services can use
    to encrypt traffic with.

    Args:
      keyname: A str representing the SSH keypair name used for this AppScale
        deployment.
      is_verbose: A bool that indicates if we want to print out the certificate
        generation to stdout or not.
    """
    cls.shell("openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 " + \
      "-subj '/C=US/ST=Foo/L=Bar/O=AppScale/CN=appscale.com' " + \
      "-keyout {0} -out {1}". \
      format(LocalState.get_private_key_location(keyname),
      LocalState.get_certificate_location(keyname)), is_verbose, stdin=None)


  @classmethod
  def get_key_path_from_name(cls, keyname):
    """Determines the location where the SSH private key used to log into the
    virtual machines in this AppScale deployment can be found.

    Args:
      keyname: A str that indicates the name of the SSH keypair that
        uniquely identifies this AppScale deployment.
    Returns:
      A str that indicates where the private key can be found.
    """
    for local_path in cls.VALID_KEY_PATHS:
      key_file_path = local_path + keyname + ".key"
      if os.path.isfile(key_file_path):
        return key_file_path

  @classmethod
  def get_private_key_location(cls, keyname):
    """Determines the location where the private key used to sign the
    self-signed certificate used for this AppScale deployment can be found.

    Args:
      keyname: A str that indicates the name of the SSH keypair that
        uniquely identifies this AppScale deployment.
    Returns:
      A str that indicates where the private key can be found.
    """
    return cls.LOCAL_APPSCALE_PATH + keyname + "-key.pem"


  @classmethod
  def get_certificate_location(cls, keyname):
    """Determines the location where the self-signed certificate for this
    AppScale deployment can be found.

    Args:
      keyname: A str that indicates the name of the SSH keypair that
        uniquely identifies this AppScale deployment.
    Returns:
      A str that indicates where the self-signed certificate can be found.
    """
    return cls.LOCAL_APPSCALE_PATH + keyname + "-cert.pem"


  @classmethod
  def get_locations_yaml_location(cls, keyname):
    """Determines the location where the YAML file can be found that contains
    information not related to service placement (e.g., what cloud we're
    running on, security group names).

    Args:
      keyname: A str that indicates the name of the SSH keypair that
        uniquely identifies this AppScale deployment.
    Returns:
      A str that indicates where the locations.yaml file can be found.
    """
    return cls.LOCAL_APPSCALE_PATH + "locations-" + keyname + ".yaml"


  @classmethod
  def get_locations_json_location(cls, keyname):
    """Determines the location where the JSON file can be found that contains
    information related to service placement (e.g., where machines can be found
    and what services they run).

    Args:
      keyname: A str that indicates the name of the SSH keypair that
        uniquely identifies this AppScale deployment.
    Returns:
      A str that indicates where the locations.json file can be found.
    """
    return cls.LOCAL_APPSCALE_PATH + "locations-" + keyname + ".json"


  @classmethod
  def update_local_metadata(cls, options, node_layout, host, instance_id):
    """Writes a locations.yaml and locations.json file to the local filesystem,
    that the tools can use to locate machines in an AppScale deployment.

    Args:
      options: A Namespace that indicates deployment-specific parameters not
        relating to the placement strategy in use.
      node_layout: A NodeLayout that indicates the placement strategy in use
        for this deployment.
      host: A str representing the location we can reach an AppController at.
      instance_id: The instance ID (if running in a cloud environment)
        associated with the given host.
    """
    # find out every machine's IP address and what they're doing
    acc = AppControllerClient(host, cls.get_secret_key(options.keyname))
    all_ips = [str(ip) for ip in acc.get_all_public_ips()]
    role_info = acc.get_role_info()

    infrastructure = options.infrastructure or 'xen'

    # write our yaml metadata file
    yaml_contents = {
      'load_balancer' : str(host),
      'instance_id' : str(instance_id),
      'table' : options.table,
      'secret' : cls.get_secret_key(options.keyname),
      'db_master' : node_layout.db_master().public_ip,
      'ips' : all_ips,
      'infrastructure' : infrastructure,
      'group' : options.group,
    }

    if infrastructure != "xen":
      yaml_contents['zone'] = options.zone

    if infrastructure == "gce":
      yaml_contents['project'] = options.project

    with open(cls.get_locations_yaml_location(options.keyname), 'w') \
        as file_handle:
      file_handle.write(yaml.dump(yaml_contents, default_flow_style=False))

    # and now we can write the json metadata file
    with open(cls.get_locations_json_location(options.keyname), 'w') \
        as file_handle:
      file_handle.write(json.dumps(role_info))


  @classmethod
  def get_from_yaml(cls, keyname, tag):
    """Reads the YAML-encoded metadata on disk and returns the value associated
    with the given tag.

    Args:
      keyname: A str that indicates the name of the SSH keypair that
        uniquely identifies this AppScale deployment.
      tag: A str that indicates what we should look for in the YAML file.
    """
    with open(cls.get_locations_yaml_location(keyname), 'r') as file_handle:
      locations_yaml = yaml.safe_load(file_handle.read())
      return locations_yaml[tag]


  @classmethod
  def get_local_nodes_info(cls, keyname):
    """Reads the JSON-encoded metadata on disk and returns a list that indicates
    which machines run each API service in this AppScale deployment.

    Args:
      keyname: A str that represents an SSH keypair name, uniquely identifying
        this AppScale deployment.
    Returns:
      A list of dicts, where each dict contains information on a single machine
      in this AppScale deployment.
    Raises:
      BadConfigurationException: If there is no JSON-encoded metadata file
        named after the given keyname.
    """
    if not os.path.exists(cls.get_locations_json_location(keyname)):
      raise BadConfigurationException("AppScale does not appear to be " + \
        "running with keyname {0}".format(keyname))

    with open(cls.get_locations_json_location(keyname), 'r') as file_handle:
      return json.loads(file_handle.read())


  @classmethod
  def get_host_for_role(cls, keyname, role):
    """ Gets the ip of the host the given role runs on.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
      role: A str, the role we are looking up the host for.
    """
    for node in cls.get_local_nodes_info(keyname):
      if role in node["jobs"]:
        return node["public_ip"]


  @classmethod
  def are_disks_used(cls, keyname):
    """Queries the locations.json file to see if any persistent disks are being
    used in this AppScale deployment.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    Returns:
      True if any persistent disks are used, and False otherwise.
    """
    disks = [node.get("disk") for node in cls.get_local_nodes_info(keyname)]
    for disk in disks:
      if disk:
        return True
    return False


  @classmethod
  def encrypt_password(cls, username, password):
    """Salts the given password with the provided username and encrypts it.

    Args:
      username: A str representing the username whose password we wish to
        encrypt.
      password: A str representing the password to encrypt.
    Returns:
      The SHA1-encrypted password.
    """
    return hashlib.sha1(username + password).hexdigest()


  @classmethod
  def get_login_host(cls, keyname):
    """Searches through the local metadata to see which virtual machine runs the
    login service.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    Returns:
      A str containing the host that runs the login service.
    """
    return cls.get_host_with_role(keyname, 'login')


  @classmethod
  def get_host_with_role(cls, keyname, role):
    """Searches through the local metadata to see which virtual machine runs the
    specified role.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
      role: A str indicating the role to search for.
    Returns:
      A str containing the host that runs the specified service.
    """
    nodes = cls.get_local_nodes_info(keyname)
    for node in nodes:
      if role in node['jobs']:
        return node['public_ip']
    raise AppScaleException("Couldn't find a {0} node.".format(role))


  @classmethod
  def get_all_public_ips(cls, keyname):
    """Searches through the local metadata to get all of the public IPs or FQDNs
    for machines in this AppScale deployment.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    Returns:
      A list containing all the public IPs or FQDNs in this AppScale deployment.
    """
    nodes = cls.get_local_nodes_info(keyname)
    return [node['public_ip'] for node in nodes]


  @classmethod
  def get_credentials(cls, is_admin=True):
    """Queries the user for the username and password that should be set for the
    cloud administrator's account in this AppScale deployment.

    Args:
      is_admin: A bool that indicates if we should be prompting the user for an
        admin username/password or not.

    Returns:
      A tuple containing the username and password that the user typed in.
    """
    username, password = None, None

    username = cls.get_username_from_stdin(is_admin)
    password = cls.get_password_from_stdin()
    return username, password


  @classmethod
  def get_username_from_stdin(cls, is_admin):
    """Asks the user for the name of the e-mail address that should be made an
    administrator on their AppScale cloud or App Engine application.

    Returns:
      A str containing the e-mail address the user typed in.
    """
    while True:
      if is_admin:
        username = raw_input('Enter your desired admin e-mail address: ')
      else:
        username = raw_input('Enter your desired e-mail address: ')

      username = username.lstrip().rstrip()
      email_regex = \
        '^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$'
      if re.match(email_regex, username):
        return username
      else:
        AppScaleLogger.warn('Invalid e-mail address. Please try again.')


  @classmethod
  def get_password_from_stdin(cls):
    """Asks the user for the password that should be used for their user
    account.

    Args:
      username: A str representing the email address associated with the user's
        account.
    Returns:
      The SHA1-hashed version of the password the user typed in.
    """
    while True:
      password = getpass.getpass('Enter new password: ')
      if len(password) < 6:
        AppScaleLogger.warn('Password must be at least 6 characters long')
        continue
      password_confirmation = getpass.getpass('Confirm password: ')
      if password == password_confirmation:
        return password
      else:
        AppScaleLogger.warn('Passwords entered do not match. Please try again.')


  @classmethod
  def map_to_array(cls, the_map):
    """Converts a dict into list. Given a map {k1:v1, k2:v2,...kn:vn}, this will
    return a list [k1,v1,k2,v2,...,kn,vn].

    Args:
      the_map: A dictionary of objects to convert into a list.

    Returns:
      A list containing all the keys and values in the input dictionary.
    """
    the_list = []
    for key, value in the_map.items():
      the_list.append(key)
      the_list.append(value)
    return the_list


  @classmethod
  def get_infrastructure(cls, keyname):
    """Reads the locations.yaml file to see if this AppScale deployment is
    running over a cloud infrastructure or a virtualized cluster.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    Returns:
      The name of the cloud infrastructure that AppScale is running over, or
      'xen' if running over a virtualized cluster.
    """
    with open(cls.get_locations_yaml_location(keyname), 'r') as file_handle:
      return yaml.safe_load(file_handle.read())["infrastructure"]


  @classmethod
  def get_group(cls, keyname):
    """Reads the locations.yaml file to see what security group was created for
    this AppScale deployment.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    Returns:
      The name of the security group used for this AppScale deployment.
    """
    with open(cls.get_locations_yaml_location(keyname), 'r') as file_handle:
      return yaml.safe_load(file_handle.read())["group"]


  @classmethod
  def get_project(cls, keyname):
    """Reads the locations.yaml file to see what project ID is used to interact
    with Google Compute Engine in this AppScale deployment.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    Returns:
      A str containing the project ID used for this AppScale deployment.
    """
    with open(cls.get_locations_yaml_location(keyname), 'r') as file_handle:
      return yaml.safe_load(file_handle.read())["project"]


  @classmethod
  def get_zone(cls, keyname):
    """Reads the locations.yaml file to see what zone instances are running in
    throughout this AppScale deployment.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    Returns:
      A str containing the zone used for this AppScale deployment.
    """
    with open(cls.get_locations_yaml_location(keyname), 'r') as file_handle:
      return yaml.safe_load(file_handle.read())["zone"]


  @classmethod
  def get_client_secrets_location(cls, keyname):
    """Returns the path on the local filesystem where the client secrets JSON
    file (used to interact with Google Compute Engine) can be found.

    Args:
      keyname: A str representing the SSH keypair name used for this AppScale
        deployment.
    Returns:
      A str that corresponds to a location on the local filesystem where the
      client secrets file can be found.
    """
    return cls.LOCAL_APPSCALE_PATH + keyname + "-secrets.json"


  @classmethod
  def get_oauth2_storage_location(cls, keyname):
    """ Returns the oauth2 storage location.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    Returns:
      A path, the oauth2 storage location.
    """
    return cls.LOCAL_APPSCALE_PATH + keyname + "-oauth2.dat"


  @classmethod
  def cleanup_appscale_files(cls, keyname):
    """Removes all AppScale metadata files from this machine.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
    """
    files_to_remove = [LocalState.get_locations_yaml_location(keyname),
      LocalState.get_locations_json_location(keyname),
      LocalState.get_secret_key_location(keyname)]

    for file_to_remove in files_to_remove:
      if os.path.exists(file_to_remove):
        os.remove(file_to_remove)


  @classmethod
  def shell(cls, command, is_verbose, num_retries=DEFAULT_NUM_RETRIES,
    stdin=None):
    """Executes a command on this machine, retrying it up to five times if it
    initially fails.

    Args:
      command: A str representing the command to execute.
      is_verbose: A bool that indicates if we should print the command we are
        executing to stdout.
      num_retries: The number of times we should try to execute the given
        command before aborting.
      stdin: A str that is passes as standard input to the process
    Returns:
      A str with both the standard output and standard error produced when the
      command executes.
    Raises:
      ShellException: If, after five attempts, executing the named command
      failed.
    """
    tries_left = num_retries
    try:
      while tries_left:
        AppScaleLogger.verbose("shell> {0}".format(command), is_verbose)
        the_temp_file = tempfile.NamedTemporaryFile()
        if stdin is not None:
          stdin_strio = tempfile.TemporaryFile()
          stdin_strio.write(stdin)
          stdin_strio.seek(0)
          AppScaleLogger.verbose("       stdin str: {0}"\
            .format(stdin), is_verbose)
          result = subprocess.Popen(command, shell=True, stdout=the_temp_file,
            stdin=stdin_strio, stderr=subprocess.STDOUT)
        else:
          result = subprocess.Popen(command, shell=True, stdout=the_temp_file,
            stderr=subprocess.STDOUT)
        AppScaleLogger.verbose("       stdout buffer: {0}"\
          .format(the_temp_file.name), is_verbose)
        result.wait()
        if stdin is not None:
          stdin_strio.close()
        if result.returncode == 0:
          the_temp_file.seek(0)
          output = the_temp_file.read()
          the_temp_file.close()
          return output
        tries_left -= 1
        if tries_left:
          the_temp_file.close()
          AppScaleLogger.verbose("Command failed. Trying again momentarily." \
            .format(command), is_verbose)
        else:
          the_temp_file.seek(0)
          output = the_temp_file.read()
          the_temp_file.close()
          if stdin:
            raise ShellException("Executing command '{0} {1}' failed:\n{2}"\
                    .format(command, stdin, output))
          else:
            raise ShellException("Executing command '{0}' failed:\n{1}"\
                    .format(command, output))
        time.sleep(1)
    except OSError as os_error:
      if stdin:
        raise ShellException("Error executing command: '{0} {1}':{2}"\
                .format(command, stdin, os_error))
      else:
        raise ShellException("Error executing command: '{0}':{1}"\
                .format(command, os_error))


  @classmethod
  def require_ssh_commands(cls, needs_expect, is_verbose):
    """Checks to make sure the commands needed to set up passwordless SSH
    access are installed on this machine.

    Args:
      needs_expect: A bool that indicates if we should also check for the
        'expect' command.
      is_verbose: A bool that indicates if we should print how we check for
        each command to stdout.
    Raises:
      BadConfigurationException: If any of the required commands aren't present
        on this machine.
    """
    required_commands = ['ssh-keygen', 'ssh-copy-id']
    if needs_expect:
      required_commands.append('expect')

    for command in required_commands:
      try:
        cls.shell("hash {0}".format(command), is_verbose)
      except ShellException:
        raise BadConfigurationException("Couldn't find {0} in your PATH."
          .format(command))


  @classmethod
  def generate_rsa_key(cls, keyname, is_verbose):
    """Generates a new RSA public and private keypair, and saves it to the
    local filesystem.

    Args:
      keyname: The SSH keypair name that uniquely identifies this AppScale
        deployment.
      is_verbose: A bool that indicates if we should print the ssh-keygen
        command to stdout.
    """
    private_key = cls.LOCAL_APPSCALE_PATH + keyname
    public_key = private_key + ".pub"

    if os.path.exists(public_key):
      os.remove(public_key)

    if os.path.exists(private_key):
      os.remove(private_key)

    cls.shell("ssh-keygen -t rsa -N '' -f {0}".format(private_key), is_verbose)
    os.chmod(public_key, 0600)
    os.chmod(private_key, 0600)
    shutil.copy(private_key, private_key + ".key")
    return public_key, private_key


  @classmethod
  def extract_tgz_app_to_dir(cls, tar_location, is_verbose):
    """Extracts the given tar.gz file to a randomly generated location and
    returns that location.

    Args:
      archive_location: The location on the local filesystem where the tar.gz
        file to extract can be found.
      is_verbose: A bool that indicates if we should print the command we
        execute to stdout.
    Returns:
      The location on the local filesystem where the file was extracted
        to.
    """
    return cls.extract_app_to_dir(tar_location, "tar zxvf", is_verbose)


  @classmethod
  def extract_zip_app_to_dir(cls, zip_location, is_verbose):
    """Extracts the given zip file to a randomly generated location and
    returns that location.

    Args:
      archive_location: The location on the local filesystem where the zip file
        to extract can be found.
      is_verbose: A bool that indicates if we should print the command we
        execute to stdout.
    Returns:
      The location on the local filesystem where the file was extracted
        to.
    """
    return cls.extract_app_to_dir(zip_location, "unzip", is_verbose)


  @classmethod
  def extract_app_to_dir(cls, archive_location, extract_command, is_verbose):
    """Extracts the given file to a randomly generated location and returns that
    location.

    Args:
      archive_location: The location on the local filesystem where the file
        to extract can be found.
      extract_command: The command and flags necessary to extract the archived
        file.
      is_verbose: A bool that indicates if we should print the command we
        execute to stdout.
    Returns:
      The location on the local filesystem where the file was extracted
        to.
    """
    extracted_location = "/tmp/appscale-app-{0}".format(str(uuid.uuid4()) \
      .replace('-', '')[:8])

    os.mkdir(extracted_location)
    cls.shell("cd {0} && {1} '{2}'".format(extracted_location, extract_command,
      os.path.abspath(archive_location)), is_verbose)

    file_list = os.listdir(extracted_location)
    if len(file_list) > 0:
      # Users can upload an archive containing their application or a directory
      # containing their application. To see which case this is, we count how
      # many files are present in the archive. As some platforms will inject a
      # dot file into every directory, we shouldn't consider those when trying
      # to find out if this archive is just a directory or not (because the
      # presence of the dot file will cause our count to be incorrect).
      file_list[:] = [itm for itm in file_list if itm[0] != '.']
      included_dir = extracted_location + os.sep + file_list[0]
      if len(file_list) == 1 and os.path.isdir(included_dir):
        extracted_location = included_dir

    return extracted_location


  @classmethod
  def generate_crash_log(cls, exception, stacktrace):
    """Writes information to the local filesystem about an uncaught exception
    that killed an AppScale Tool's execution, to aid in debugging at a later
    time.

    Args:
      exception: The Exception that crashed executing an AppScale Tool, whose
        information we want to log for debugging purposes.
      stacktrace: A str that contains the newline-separated stacktrace
        corresponding to the given exception.
    Returns:
      The location on the filesystem where the crash log was written to.
    """
    crash_log_filename = '{0}log-{1}'.format(
      LocalState.LOCAL_APPSCALE_PATH, uuid.uuid4())

    try:
      locale.setlocale(locale.LC_ALL, '')
      this_locale = locale.getlocale()[0]
    except locale.Error:
      this_locale = "unknown"

    log_info = {
      # System-specific information
      'platform' : platform.platform(),
      'runtime' : platform.python_implementation(),
      'locale' : this_locale,

      # Crash-specific information
      'exception' : exception.__class__.__name__,
      'message' : str(exception),
      'stacktrace' : stacktrace.rstrip(),

      # AppScale Tools-specific information
      'tools_version' : APPSCALE_VERSION
    }

    # If LOCAL_APPSCALE_PATH doesn't exist, create it so that we can write the
    # crash log.
    if not os.path.exists(LocalState.LOCAL_APPSCALE_PATH):
      os.mkdir(LocalState.LOCAL_APPSCALE_PATH)

    with open(crash_log_filename, 'w') as file_handle:
      for key, value in log_info.iteritems():
        file_handle.write("{0} : {1}\n\n".format(key, value))

    AppScaleLogger.warn(str(exception))
    AppScaleLogger.log("\nA log with more information is available " \
      "at\n{0}.".format(crash_log_filename))
    return crash_log_filename


  @classmethod
  def ensure_user_wants_to_terminate(cls):
    """ Asks the user for confirmation before we terminate their AppScale
    deployment.

    Raises:
      AppScaleException: If the user does not want to terminate their
        AppScale deployment.
    """
    cls.confirm_or_abort("Terminating AppScale will delete all stored data.")


  @classmethod
  def ensure_user_wants_to_run_without_disks(cls):
    """ Asks the user for confirmation before we start AppScale in a cloud
    environment without any persistent disks to save their data.

    Raises:
      AppScaleException: If the user does not want to start AppScale without
        persistent disks.
    """
    cls.confirm_or_abort("Starting AppScale without specifying persistent " +
      "disks means your data will not be saved when your cloud is destroyed.")


  @classmethod
  def confirm_or_abort(cls, message):
    """ Displays confirmation message and collects user's choice.

    Args:
      message: A str, the message to be displayed.
    Raises:
      AppScaleException: If the user chooses to terminate AppScale.
    """
    AppScaleLogger.warn(message)
    confirm = raw_input("Are you sure you want to do this? (Y/N) ")
    if confirm.lower() == 'y' or confirm.lower() == 'yes':
      return
    else:
      raise AppScaleException('AppScale termination was cancelled.')


  @classmethod
  def ensure_appscalefile_is_up_to_date(cls):
    """ Examines the AppScalefile in the current working directory to make sure
    it specifies a keyname and group, updating it if it does not.

    This scenario can occur if the user wants us to automatically generate a
    keyname and group for them (in which case they don't specify either).

    Returns:
      True if the AppScalefile was up to date, or False if there were changes
      made to make it up to date.

    Raises:
      AppScalefileException: If there is no AppScalefile in the current working
        directory.
    """
    appscalefile_path = os.getcwd() + os.sep + "AppScalefile"
    if not os.path.exists(appscalefile_path):
      raise AppScalefileException("Couldn't find an AppScale file at {0}" \
        .format(appscalefile_path))

    file_contents = ''
    with open(appscalefile_path) as file_handle:
      file_contents = file_handle.read()

    yaml_contents = yaml.safe_load(file_contents)

    # Don't write to the AppScalefile if there are no changes to make to it.
    if 'keyname' in yaml_contents and 'group' in yaml_contents:
      return True

    file_contents += "\n# Automatically added by the AppScale Tools: "

    random_suffix = str(uuid.uuid4()).replace('-', '')
    cloud_name = "appscale{0}".format(random_suffix)
    if 'keyname' not in yaml_contents:
      file_contents += "\nkeyname : {0}".format(cloud_name)

    if 'group' not in yaml_contents:
      file_contents += "\ngroup : {0}".format(cloud_name)

    with open(appscalefile_path, 'w') as file_handle:
      file_handle.write(file_contents)

    return False
