#!/usr/bin/env python


# General-purpose Python libraries
import os
import socket
import re
import yaml
from xml.etree import ElementTree


# AppScale-specific imports
from .admin_client import DEFAULT_SERVICE
from .appscale_logger import AppScaleLogger
from .custom_exceptions import AppEngineConfigException
from .custom_exceptions import AppScaleException


class AppEngineHelper(object):
  """AppEngineHelper provides convenience methods that can be used to parse
  configuration files found in App Engine apps, and ensure that they are
  configured in such a way that AppScale can host them.
  """


  # The version of the App Engine SDK that AppScale currently supports.
  SUPPORTED_SDK_VERSION = '1.8.4'


  # A regular expression that can be used to see if the given configuration file
  # is a YAML File.
  FILE_IS_YAML = re.compile(r'\.yaml\Z')


  # A list of language runtimes that App Engine apps can be written in.
  ALLOWED_RUNTIMES = ("python27", "java", "go", "php")


  # A list of language runtimes that AppScale no longer supports.
  DEPRECATED_RUNTIMES = ("python")


  # A list of the appids reserved for internal AppScale use.
  DISALLOWED_APP_IDS = ("none", "apichecker", "appscaledashboard")


  # A regular expression that matches valid application IDs.
  APP_ID_REGEX = re.compile(r'\A(\d|[a-z]|[A-Z]|-)+\Z')


  # A message to be displayed to the user, in case the given application ID
  # does not comply with the corresponding regular expression.
  REGEX_MESSAGE = "Valid application IDs contain only letters, numbers " + \
                  "and/or '-'."


  # The prefix of the GAE Java SDK jar name.
  JAVA_SDK_JAR_PREFIX = 'appengine-api-1.0-sdk'


  # The configuration file for Java Apps.
  APPENGINE_WEB_XML = 'appengine-web.xml'


  # The directory that contains useful libraries for Java Apps.
  LIB = 'lib'


  # The namespace used for appengine-web.xml.
  XML_NAMESPACE = '{http://appengine.google.com/ns/1.0}'


  @classmethod
  def read_file(cls, path):
    """Reads the file at the given location, returning its contents.

    Args:
      path: The location on the filesystem that we should read from.
    Returns:
      A str containing the contents of the file.
    """
    with open(path, 'r') as file_handle:
      return file_handle.read()


  @classmethod
  def get_app_yaml_location(cls, app_dir):
    """Returns the location that we expect an app.yaml file to be found within
    an App Engine application.

    Args:
      app_dir: The location on the filesystem where the App Engine application
        is located.
    Returns:
      The location where we can expect to find an app.yaml file for the given
      application.
    """
    return app_dir + os.sep + "app.yaml"


  @classmethod
  def get_appengine_web_xml_location(cls, app_dir):
    """Returns the location that we expect an appengine-web.xml file to be found
    within an App Engine application.

    Args:
      app_dir: The location on the filesystem where the App Engine application
        is located.
    Returns:
      The location of the appengine-web.xml file for the given application.
    """
    for root, sub_dirs, files in os.walk(app_dir):
      for file in files:
        if file == cls.APPENGINE_WEB_XML:
          return os.path.abspath(os.path.join(root, file))


  @classmethod
  def is_sdk_mismatch(cls, app_dir):
    """ Returns if the sdk jar is the right version within an App Engine
    application.

    Args:
      app_dir: The location on the filesystem where the App Engine application
        is located.
    Returns:
      A boolean value indicating if the user may have an sdk version
      compatibility error with AppScale.
    """
    target_jar = cls.JAVA_SDK_JAR_PREFIX + '-' + cls.SUPPORTED_SDK_VERSION \
      + '.jar'
    paths = cls.get_appengine_lib_locations(app_dir)
    mismatch = True
    for path in paths:
      lib_files = os.listdir(path)
      for jar_file in lib_files:
        if target_jar in jar_file:
          mismatch = False
          break
      # If the SDK is found, terminate lookup.
      if not mismatch:
        break
    return mismatch

  @classmethod
  def get_appengine_lib_locations(cls, app_dir):
    """ Returns the locations of all lib folders within an App Engine
    application.

    Args:
      app_dir: The location on the filesystem where the App Engine application
        is located.
    Returns:
      A list, all the lib folder paths in the given application.
    """
    paths = []
    for root, sub_dirs, files in os.walk(app_dir):
      for dir in sub_dirs:
        if dir == cls.LIB:
          paths.append(os.path.abspath(os.path.join(root, dir)))
    return paths

  @classmethod
  def get_app_id_from_app_config(cls, app_dir):
    """Checks the configuration file packages with the given App Engine app to
    determine what the user has set as this application's name.

    Args:
      app_dir: The directory on the local filesystem where the App Engine
        application can be found.
    Returns:
      A str indicating the application ID for this application.
    Raises:
      AppEngineConfigException: If there is no application ID set for this
        application.
    """
    app_config_file = cls.get_config_file_from_dir(app_dir)
    if cls.FILE_IS_YAML.search(app_config_file):
      yaml_contents = yaml.safe_load(cls.read_file(app_config_file))
      if 'application' in yaml_contents and yaml_contents['application'] != '':
        project_id = yaml_contents['application']
      else:
        raise AppEngineConfigException("No valid application ID found in " +
          "your app.yaml. " + cls.REGEX_MESSAGE)
    else:
      root = ElementTree.parse(app_config_file).getroot()
      app_element = root.find('{}application'.format(cls.XML_NAMESPACE))
      if app_element is None:
        raise AppEngineConfigException(
          'No application ID found in appengine-web.xml')

      project_id = app_element.text

    cls.validate_app_id(project_id)
    return project_id

  @classmethod
  def get_service_id(cls, app_dir):
    """ Retrieves the service ID from the application configuration.

    Args:
      app_dir: The directory on the local filesystem where the App Engine
        application can be found.
    """
    app_config_file = cls.get_config_file_from_dir(app_dir)
    if cls.FILE_IS_YAML.search(app_config_file):
      yaml_contents = yaml.safe_load(cls.read_file(app_config_file))
      return yaml_contents.get('module', DEFAULT_SERVICE)
    else:
      root = ElementTree.parse(app_config_file).getroot()
      service_element = root.find('{}module'.format(cls.XML_NAMESPACE))
      if service_element is None:
        return DEFAULT_SERVICE

      return service_element.text

  @classmethod
  def warn_if_version_defined(cls, app_dir, test=False):
    """ Warns the user if version is defined in the application configuration.

    Args:
      app_dir: The directory on the local filesystem where the App Engine
        application can be found.
      test: A boolean indicating that the tools are in test mode.
    Raises:
      AppScaleException: If version is defined and user decides to cancel.
    """
    message = ''
    app_config_file = cls.get_config_file_from_dir(app_dir)
    if cls.FILE_IS_YAML.search(app_config_file):
      yaml_contents = yaml.safe_load(cls.read_file(app_config_file))
      if yaml_contents.get('version') is not None:
        module = yaml_contents.get('module', 'default')
        message = ('The version element is not supported in app.yaml. '
                   'Module {} will be overwritten.'.format(module))
    else:
      app_config = ElementTree.parse(app_config_file).getroot()
      if app_config.find('{}version'.format(cls.XML_NAMESPACE)) is not None:
        module_element = app_config.find('{}module'.format(cls.XML_NAMESPACE))
        if module_element is None:
          module = 'default'
        else:
          module = module_element.text

        message = ('The version element is not supported in appengine-web.xml.'
                   ' Module {} will be overwritten.'.format(module))

    if message:
      AppScaleLogger.log(message)
      if not test:
        response = raw_input('Continue? (y/N) ')
        if response.lower() not in ['y', 'yes']:
          raise AppScaleException('Cancelled deploy operation')

  @classmethod
  def get_app_runtime_from_app_config(cls, app_dir):
    """Checks the configuration file packaged with the given App Engine app to
    determine what language runtime should be used to deploy this app.

    Currently there are only four runtimes: python (Python 2.5), java (Java),
    go (Go), and python27 (Python 2.7)

    Args:
      app_dir: The directory on the local filesystem where the App Engine
        application can be found.
    Returns:
      A str indicating which runtime should be used to run this application.
    Raises:
      AppEngineConfigException: If there is no runtime set for this application.
    """
    app_config_file = cls.get_config_file_from_dir(app_dir)
    if cls.FILE_IS_YAML.search(app_config_file):
      yaml_contents = yaml.safe_load(cls.read_file(app_config_file))
      if 'runtime' in yaml_contents and yaml_contents['runtime'] in \
        cls.ALLOWED_RUNTIMES:
        return yaml_contents['runtime']
      elif 'runtime' in yaml_contents and yaml_contents['runtime'] in \
        cls.DEPRECATED_RUNTIMES:
        raise AppEngineConfigException("This runtime is deprecated and no " + \
          "longer supported.")
      else:
        raise AppEngineConfigException("No runtime set in your app.yaml")
    else:
      return 'java'

  @classmethod
  def is_threadsafe(cls, app_dir):
    """ Retrieves threadsafe value from version configuration.

    Args:
      app_dir: The directory containing the version source code.
    Returns:
      A boolean containing the value of threadsafe.
    Raises:
      AppEngineConfigException if the version is configured incorrectly.
    """
    app_config_file = cls.get_config_file_from_dir(app_dir)
    if cls.FILE_IS_YAML.search(app_config_file):
      yaml_contents = yaml.safe_load(cls.read_file(app_config_file))
      try:
        threadsafe = yaml_contents['threadsafe']
      except KeyError:
        raise AppEngineConfigException(
          '"threadsafe" must be definined in your app.yaml.')
    else:
      root = ElementTree.parse(app_config_file).getroot()
      threadsafe_element = root.find('{}threadsafe'.format(cls.XML_NAMESPACE))
      if threadsafe_element is None:
        raise AppEngineConfigException(
          '"threadsafe" must be definined in your appengine-web.xml.')

      if threadsafe_element.text.lower() not in ['true', 'false']:
        raise AppEngineConfigException(
          'Invalid "threadsafe" value in your app configuration. '
          'It must be either "true" or "false".')

      threadsafe = threadsafe_element.text.lower() == 'true'

    if not isinstance(threadsafe, bool):
      raise AppEngineConfigException('"threadsafe" must be a boolean value.')
    return threadsafe

  @classmethod
  def get_env_vars(cls, app_dir):
    """ Retrieves environment varibles from the version configuration.

    Args:
      app_dir: The directory containing the version source code.
    Returns:
      A dictionary containing environment variables.
    """
    app_config_file = cls.get_config_file_from_dir(app_dir)
    if cls.FILE_IS_YAML.search(app_config_file):
      yaml_contents = yaml.safe_load(cls.read_file(app_config_file))
      return yaml_contents.get('env_variables', {})
    else:
      app_config = ElementTree.parse(app_config_file).getroot()
      env_vars = app_config.find('{}env-variables'.format(cls.XML_NAMESPACE))
      if env_vars is None:
        return {}

      return {var.attrib['name']: var.attrib['value'] for var in env_vars}

  @classmethod
  def get_inbound_services(cls, app_dir):
    """ Retrieves inbound services from the version configuration.

    Args:
      app_dir: The directory containing the version source code.
    Returns:
      A list of inbound service types or None.
    """
    app_config_file = cls.get_config_file_from_dir(app_dir)
    if cls.FILE_IS_YAML.search(app_config_file):
      yaml_contents = yaml.safe_load(cls.read_file(app_config_file))
      inbound_services = yaml_contents.get('inbound_services')
      if inbound_services is None:
        return None
    else:
      app_config = ElementTree.parse(app_config_file).getroot()
      inbound_services = app_config.find(
        '{}inbound-services'.format(cls.XML_NAMESPACE))
      if inbound_services is None:
        return None

      inbound_services = [service.text for service in inbound_services]

    return ['INBOUND_SERVICE_{}'.format(service).upper()
            for service in inbound_services]

  @classmethod
  def get_config_file_from_dir(cls, app_dir):
    """Finds the location of the app.yaml or appengine-web.xml file in the
    provided App Engine app.

    Args:
      app_dir: The directory on the local filesystem where the App Engine
        application can be found.
    Returns:
      A str containing the path to the configuration file on the local
        filesystem.
    Raises:
      AppEngineConfigException: If there is no configuration file for this
      application.
    """
    if os.path.exists(cls.get_app_yaml_location(app_dir)):
      return cls.get_app_yaml_location(app_dir)
    elif os.path.exists(cls.get_appengine_web_xml_location(app_dir)):
      return cls.get_appengine_web_xml_location(app_dir)
    else:
      raise AppEngineConfigException("Couldn't find an app.yaml or " +
        "appengine-web.xml file in {0}".format(app_dir))


  @classmethod
  def validate_app_id(cls, app_id):
    """Checks the given app_id to make sure that it represents an app_id that
    we can run within AppScale.

    Args:
      app_id: A str that represents the application ID.
    Raises:
      AppEngineConfigException: If the given application ID is a reserved
        app_id, or does not represent an acceptable app_id.
    """
    if app_id in cls.DISALLOWED_APP_IDS:
      raise AppEngineConfigException("{0} is a reserved appid".format(app_id))

    if not cls.APP_ID_REGEX.match(app_id):
      raise AppEngineConfigException("Invalid application ID. You can only" + \
        " use alphanumeric characters and/or '-'.")

  @classmethod
  def is_valid_ipv4_address(cls, address):
    """ Determines whether or not a string is an IP address.

    Args:
      address: A string containing a potential address.
    Returns:
      A boolean indicating whether or not the string is a valid IP address.
    """
    try:
      socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
      # The inet_pton function is not available on all platforms.
      try:
        socket.inet_aton(address)
      except socket.error:
        return False
      # Reject shortened addresses.
      return address.count('.') == 3
    except socket.error:
      return False

    return True
