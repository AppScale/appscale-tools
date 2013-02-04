#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python libraries
import os
import re
import yaml


# AppScale-specific imports
from custom_exceptions import AppEngineConfigException


class AppEngineHelper():
  """AppEngineHelper provides convenience methods that can be used to parse
  configuration files found in App Engine apps, and ensure that they are
  configured in such a way that AppScale can host them.
  """


  # A regular expression that can be used to see if the given configuration file
  # is a YAML File.
  FILE_IS_YAML = re.compile('\.yaml\Z')


  # A regular expression that can be used to find an appid in a XML file.
  JAVA_APP_ID_REGEX = re.compile('<application>([\w\d-]+)<\/application>')


  # A list of language runtimes that App Engine apps can be written in.
  ALLOWED_RUNTIMES = ("python", "python27", "java", "go")


  # A list of the appids reserved for internal AppScale use.
  DISALLOWED_APP_IDS = ("none", "auth", "login", "new_user", "load_balancer")


  # A regular expression that matches valid application IDs.
  APP_ID_REGEX = re.compile('\A(\d|[a-z]|[A-Z]|-)+\Z')


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
      The location where we can expect to find an appengine-web.xml file for the
      given application.
    """
    return app_dir + os.sep + "war" + os.sep + "WEB-INF" + os.sep + \
      "appengine-web.xml"


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
        raise AppEngineConfigException("No application id set in your app.yaml")
    else:
      xml_contents = cls.read_file(app_config_file)
      app_id_matchdata = cls.JAVA_APP_ID_REGEX.search(xml_contents)
      if app_id_matchdata:
        return app_id_matchdata.group(1)
      else:
        raise AppEngineConfigException("No application id set in your " + \
          "appengine-web.xml")


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
      else:
        raise AppEngineConfigException("No runtime set in your app.yaml")
    else:
      return 'java'


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
      raise AppEngineConfigException("Cannot use non-alphanumeric chars in " + \
        "application ID.")
