""" Miscellaneous utility functions needed by the tools. """

import errno
import os
import tarfile
import zipfile
from xml.etree import ElementTree

from .custom_exceptions import BadConfigurationException


def config_from_tar_gz(file_name, tar_location):
  """ Reads a configuration file from a source tarball.

  Args:
    file_name: A string specifying the configuration file.
    tar_location: A string specifying the location of the tarball.
  Returns:
    The contents of the configuration file.
  """
  with tarfile.open(tar_location, 'r:gz') as tar:
    candidates = [member for member in tar.getmembers()
                  if member.name.split('/')[-1] == file_name]
    if not candidates:
      return None

    shortest_path = candidates[0]
    for candidate in candidates:
      if len(candidate.name.split('/')) < len(shortest_path.name.split('/')):
        shortest_path = candidate

    config_file = tar.extractfile(shortest_path)
    try:
      return config_file.read()
    finally:
      config_file.close()


def config_from_zip(file_name, zip_location):
  """ Reads a configuration file from a source zip file.

  Args:
    file_name: A string specifying the configuration file.
    zip_location: A string specifying the location of the zip file.
  Returns:
    The contents of the configuration file.
  """
  with zipfile.ZipFile(zip_location) as zip_file:
    candidates = [member for member in zip_file.namelist()
                  if member.split('/')[-1] == file_name]
    if not candidates:
      return None

    shortest_path = candidates[0]
    for candidate in candidates:
      if len(candidate.split('/')) < len(shortest_path.split('/')):
        shortest_path = candidate

    with zip_file.extract(shortest_path) as config_file:
      return config_file.read()


def config_from_dir(file_name, source_path):
  """ Reads a configuration file from a source directory.

  Args:
    file_name: A string specifying the configuration file.
    source_path: A string specifying the location of the source directory.
  Returns:
    The contents of the configuration file.
  """
  candidates = []
  for root, _, files in os.walk(source_path):
    if file_name in files:
      candidates.append(os.path.join(root, file_name))

  if not candidates:
    return None

  shortest_path = candidates[0]
  for candidate in candidates:
    if len(candidate.split(os.sep)) < len(shortest_path.split(os.sep)):
      shortest_path = candidate

  with open(shortest_path) as config_file:
    return config_file.read()


def cron_from_xml(contents):
  """ Parses the contents of a cron.xml file.

  Args:
    contents: An XML string containing cron configuration details.
  Returns:
    A dictionary containing cron configuration details.
  """
  cron_config = {'cron': []}
  job_entries = ElementTree.fromstring(contents)
  for job_entry in job_entries:
    if job_entry.tag != 'cron':
      raise BadConfigurationException(
        'Unrecognized element in cron.xml: {}'.format(job_entry.tag))

    job = {}
    for element in job_entry:
      tag = element.tag.replace('-', '_')
      if tag == 'retry_parameters':
        params = {child.tag.replace('-', '_'): child.text for child in element}
        int_elements = ['job_retry_limit', 'min_backoff_seconds',
                        'max_backoff_seconds', 'max_doublings']
        for int_element in int_elements:
          if int_element in params:
            params[int_element] = int(params[int_element])
        job[tag] = params
      else:
        job[tag] = element.text

    cron_config['cron'].append(job)

  return cron_config


def queues_from_xml(contents):
  """ Parses the contents of a queue.xml file.

  Args:
    contents: An XML string containing queue configuration details.
  Returns:
    A dictionary containing queue configuration details.
  """
  queues = {'queue': []}
  queue_entries = ElementTree.fromstring(contents)
  for queue_entry in queue_entries:
    if queue_entry.tag == 'total-storage-limit':
      queues['total_storage_limit'] = queue_entry.text
      continue

    if queue_entry.tag != 'queue':
      raise BadConfigurationException(
        'Unrecognized element in queue.xml: {}'.format(queue_entry.tag))

    queue = {}
    for element in queue_entry:
      tag = element.tag.replace('-', '_')
      if tag == 'acl':
        queue['acl'] = [{child.tag.replace('-', '_'): child.text}
                        for child in element]
      elif tag == 'retry_parameters':
        params = {child.tag.replace('-', '_'): child.text for child in element}
        int_elements = ['task_retry_limit', 'min_backoff_seconds',
                        'max_backoff_seconds', 'max_doublings']
        for int_element in int_elements:
          if int_element in params:
            params[int_element] = int(params[int_element])
        queue['retry_parameters'] = params
      else:
        if tag in ['bucket_size', 'max_concurrent_requests']:
          queue[tag] = int(element.text)
        else:
          queue[tag] = element.text

    queues['queue'].append(queue)

  return queues


def mkdir(dir_path):
  """ Creates a directory.

  Args:
    dir_path: The path to create.
  """
  try:
    return os.makedirs(dir_path)
  except OSError as exc:
    if exc.errno == errno.EEXIST and os.path.isdir(dir_path):
      pass
    else:
      raise


class UnknownStyle(ValueError):
  pass


STYLES_MAP = {
  # Attributes:
  "bold": "\x1b[1m",
  "dim": "\x1b[2m",
  "underlined": "\x1b[4m",
  "reverse": "\x1b[7m",
  # Foreground colors:
  "black": "\x1b[30m",
  "red": "\x1b[31m",
  "green": "\x1b[32m",
  "yellow": "\x1b[33m",
  "blue": "\x1b[34m",
  "magenta": "\x1b[35m",
  "cyan": "\x1b[36m",
  "light_gray": "\x1b[37m",
  "dark_gray": "\x1b[90m",
  "light_red": "\x1b[91m",
  "light_green": "\x1b[92m",
  "light_yellow": "\x1b[93m",
  "light_blue": "\x1b[94m",
  "light_magenta": "\x1b[95m",
  "light_cyan": "\x1b[96m",
  "white": "\x1b[97m",
  # Background colors:
  "back_black": "\x1b[40m",
  "back_red": "\x1b[41m",
  "back_green": "\x1b[42m",
  "back_yellow": "\x1b[43m",
  "back_blue": "\x1b[44m",
  "back_magenta": "\x1b[45m",
  "back_cyan": "\x1b[46m",
  "back_light_gray": "\x1b[47m",
  "back_dark_gray": "\x1b[100m",
  "back_light_red": "\x1b[101m",
  "back_light_green": "\x1b[102m",
  "back_light_yellow": "\x1b[103m",
  "back_light_blue": "\x1b[104m",
  "back_light_magenta": "\x1b[105m",
  "back_light_cyan": "\x1b[106m",
  "back_white": "\x1b[107m",
}


def styled(text, *marks, **conditions):
  """
  Applies marks to text.

  Args:
    text: A text to wrap with xterm codes.
    marks: args. A list of strings representing styles to apply.
    conditions: kwargs. Only one allowed key is 'if_'
      'if_': A boolean showing if mark should be applied.

  Returns:
    Styled string.
  """
  text = unicode(text)
  if not conditions.get("if_", True):
    return text

  # Prepare xterm prefix to prepend it to the text
  try:
    styles_prefix = u"".join((STYLES_MAP[style] for style in marks))
  except KeyError as err:
    raise UnknownStyle("Unknown style ({err}). Allowed are: {styles}"
                       .format(err=err, styles=STYLES_MAP.keys().sort()))

  # Resolve collisions with styles of wrapped text
  text = text.replace(u"\x1b[0m", u"\x1b[0m{}".format(styles_prefix))

  return u"{prefix}{text}\x1b[0m".format(prefix=styles_prefix, text=text)
