#!/usr/bin/env python


# General-purpose Python libraries
import os
import socket
import re
import yaml


# AppScale-specific imports
from custom_exceptions import AppEngineConfigException


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


  # A regular expression that can be used to find an appid in a XML file.
  JAVA_APP_ID_REGEX = re.compile(r'<application>(.*)<\/application>')


  # A regular expression for finding the threadsafe key in appengine-web.xml.
  JAVA_THREADSAFE_REGEX = re.compile(r'<threadsafe>(.*)<\/threadsafe>')


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
        return yaml_contents['application']
      else:
        raise AppEngineConfigException("No valid application ID found in " +
          "your app.yaml. " + cls.REGEX_MESSAGE)
    else:
      xml_contents = cls.read_file(app_config_file)
      app_id_matchdata = cls.JAVA_APP_ID_REGEX.search(xml_contents)
      if app_id_matchdata:
        return app_id_matchdata.group(1)
      else:
        raise AppEngineConfigException("No application ID found in " +
          "your appengine-web.xml. " + cls.REGEX_MESSAGE)


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
      xml_contents = cls.read_file(app_config_file)
      try:
        threadsafe = cls.JAVA_THREADSAFE_REGEX.search(xml_contents).group(1)
      except AttributeError:
        raise AppEngineConfigException(
          '"threadsafe" must be definined in your appengine-web.xml.')

      print('threadsafe: {}'.format(threadsafe))
      if threadsafe.lower() not in ['true', 'false']:
        raise AppEngineConfigException(
          'Invalid "threadsafe" value in your app configuration. '
          'It must be either "true" or "false".')
      threadsafe = threadsafe.lower() == 'true'

    if not isinstance(threadsafe, bool):
      raise AppEngineConfigException('"threadsafe" must be a boolean value.')
    return threadsafe

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
