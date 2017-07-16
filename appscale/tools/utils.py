""" Miscellaneous utility functions needed by the tools. """

import os
import tarfile
import zipfile
from xml.etree import ElementTree


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

    with tar.extractfile(shortest_path) as config_file:
      return config_file.read()


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

    if queue_entry.tag != 'queue':
      continue

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
