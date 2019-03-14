#!/usr/bin/env python

from __future__ import absolute_import

import os
import re
import socket

from appscale.tools.appscale_logger import AppScaleLogger
from appscale.tools.custom_exceptions import AppEngineConfigException
from appscale.tools.custom_exceptions import AppScaleException


class AppEngineHelper(object):
  """AppEngineHelper provides convenience methods that can be used to parse
  configuration files found in App Engine apps, and ensure that they are
  configured in such a way that AppScale can host them.
  """

  # The version of the App Engine SDK that AppScale currently supports.
  SUPPORTED_SDK_VERSION = '1.8.4'

  # A list of the appids reserved for internal AppScale use.
  DISALLOWED_APP_IDS = ("none", "apichecker", "appscaledashboard")

  # A regular expression that matches valid application IDs.
  APP_ID_REGEX = re.compile(r'^[a-z][a-z\d\-]{5,29}$')

  # A message to be displayed to the user, in case the given application ID
  # does not comply with the corresponding regular expression.
  REGEX_MESSAGE = "Valid application IDs contain only letters, numbers " + \
                  "and/or '-'."

  # The prefix of the GAE Java SDK jar name.
  JAVA_SDK_JAR_PREFIX = 'appengine-api-1.0-sdk'

  # The directory that contains useful libraries for Java Apps.
  LIB = 'lib'

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
  def warn_if_version_defined(cls, version, test=False):
    """ Warns the user if version is defined in the application configuration.

    Args:
      version: A Version object.
      test: A boolean indicating that the tools are in test mode.
    Raises:
      AppScaleException: If version is defined and user decides to cancel.
    """
    if version.id is not None:
      AppScaleLogger.log(
        'The version element is not supported in {}. Module {} will be '
        'overwritten.'.format(version.config_type, version.service_id))
      if not test:
        response = raw_input('Continue? (y/N) ')
        if response.lower() not in ['y', 'yes']:
          raise AppScaleException('Cancelled deploy operation')

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
      raise AppEngineConfigException("Invalid application ID." + \
        " It must be 6 to 30 lowercase letters, digits, " + \
        "or hyphens. It must start with a letter.")

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
