""" Miscellaneous utility functions needed by the tools. """

import errno
import os
import tarfile
import yaml
import zipfile
from xml.etree import ElementTree

from .custom_exceptions import BadConfigurationException


def shortest_path_from_list(file_name, name_list):
  """ Determines the shortest path to a file in a list of candidates.

  Args:
    file_name: A string specifying the name of the matching candidates.
    name_list: A list of strings specifying paths.
  Returns:
    A string specifying the candidate with the shortest path or None.
  """
  candidates = [path for path in name_list if path.split('/')[-1] == file_name]
  if not candidates:
    return None

  shortest_path = candidates[0]
  for candidate in candidates:
    if len(candidate.split('/')) < len(shortest_path.split('/')):
      shortest_path = candidate

  return shortest_path


def config_from_tar_gz(file_name, tar_location):
  """ Reads a configuration file from a source tarball.

  Args:
    file_name: A string specifying the configuration file.
    tar_location: A string specifying the location of the tarball.
  Returns:
    The contents of the configuration file.
  """
  with tarfile.open(tar_location, 'r:gz') as tar:
    paths = [member.name for member in tar.getmembers()]
    shortest_path = shortest_path_from_list(file_name, paths)
    if shortest_path is None:
      return None

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
    The contents of the configuration file or None.
  """
  with zipfile.ZipFile(zip_location) as zip_file:
    shortest_path = shortest_path_from_list(file_name, zip_file.namelist())
    if shortest_path is None:
      return None

    with zip_file.extract(shortest_path) as config_file:
      return config_file.read()


def shortest_directory_path(file_name, source_path):
  """ Determines the shortest path to a given file name in a directory.

  Args:
    file_name: A string specifying the name of the candidate files.
    source_path: A string specifying the location of the directory.
  Returns:
    A string specifying the candidate with the shortest path or None.
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

  return shortest_path


def config_from_dir(file_name, source_path):
  """ Reads a configuration file from a source directory.

  Args:
    file_name: A string specifying the configuration file.
    source_path: A string specifying the location of the source directory.
  Returns:
    The contents of the configuration file or None.
  """
  shortest_path = shortest_directory_path(file_name, source_path)
  if shortest_path is None:
    return None

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


def indexes_from_xml(contents):
  """ Parses the contents of a datastore-indexes.xml file.

  Args:
    contents: An XML string containing index configuration details.
  Returns:
    A dictionary containing index configuration details.
  """
  index_entries = ElementTree.fromstring(contents)
  if index_entries.tag != 'datastore-indexes':
    raise BadConfigurationException(
      'datastore-indexes.xml should have a single root element named '
      'datastore-indexes')

  indexes = {'indexes': []}
  for index_entry in index_entries:
    if index_entry.tag != 'datastore-index':
      raise BadConfigurationException(
        'Unrecognized element in datastore-indexes.xml: '
        '{}'.format(index_entry.tag))

    try:
      index = {'kind': index_entry.attrib['kind']}
    except KeyError:
      raise BadConfigurationException('Index missing "kind" attribute')

    if 'ancestor' in index_entry.attrib:
      index['ancestor'] = index_entry.attrib['ancestor']
      if index['ancestor'].lower() not in ('yes', 'no', 'true', 'false'):
        raise BadConfigurationException(
          'Invalid ancestor value: {}'.format(index['ancestor']))

    index['properties'] = []
    if len(index_entry) < 1:
      raise BadConfigurationException(
        'All index entries must have at least one property')

    for prop in index_entry:
      if prop.tag != 'property':
        raise BadConfigurationException(
          'Unrecognized element in datastore-index: {}'.format(prop.tag))

      try:
        prop_details = {'name': prop.attrib['name']}
      except KeyError:
        raise BadConfigurationException('Property missing "name" attribute')

      if 'direction' in prop.attrib:
        prop_details['direction'] = prop.attrib['direction']
        if prop_details['direction'].lower() not in ('asc', 'desc'):
          raise BadConfigurationException(
            'Invalid direction value: {}'.format(prop_details['direction']))

      index['properties'].append(prop_details)

    indexes['indexes'].append(index)

  return indexes


def get_indexes(source_location, fetch_function):
  """ Retrieves a list of index definitions from a source's configuration.

  Args:
    source_location: A string specifying the location of the source code.
    fetch_function: The function used to find a file within the source.
  Returns:
    A list of dictionaries containing index definition details or None.
  """
  index_config = fetch_function('index.yaml', source_location)
  if index_config is not None:
    return yaml.safe_load(index_config)

  index_config = fetch_function('datastore-indexes.xml', source_location)
  if index_config is not None:
    return indexes_from_xml(index_config)

  index_config = fetch_function('datastore-indexes-auto.xml', source_location)
  if index_config is not None:
    return indexes_from_xml(index_config)


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
