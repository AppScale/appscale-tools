#!/usr/bin/python

"""Simple multithreaded HTTP request driver for HTTPMR.

Command-line tool for driving HTTPMR operations.  Spawns multiple threads for
concurrent shard operation, handles statistics collection and operation failure
retries.

Sample usage:

driver.py --httpmr_base=http://your.app.com/httpmr_base_url \
    --max_operations_inflight=10 \
    --max_per_operation_failures=10
"""

import HTMLParser
import logging
import optparse
import time
import sys
import threading
import urllib
import urllib2
import urlparse

MAP_MASTER_TASK_NAME = "map_master"
REDUCE_MASTER_TASK_NAME = "reduce_master"
INTERMEDIATE_DATA_CLEANUP_MASTER_TASK_NAME = "cleanup_master"
OPERATION_TIMEOUT_SEC = "operation_timeout"
MIN_OPERATION_TIMEOUT_SEC_VALUE = 0.5
INFINITE_PARAMETER_VALUE = -1


class Error(Exception):
  """Base class for all driver-specific Exceptions."""


class UncrecoverableOperationError(Error):
  """Base class for all fatal operation errors."""


class TooManyTriesError(UncrecoverableOperationError):
  """An operation has been tried too many times without success."""


class OperationResult(object):
  """Simple data object that holds the result of a map or reduce operation.
  
  To use, set public instance parameters directly.  Not meant to be used outside
  the context of this module.
  """
  
  def __init__(self):
    self.url = None
    self.next_url = None
    self.errors = []
    self.tries = 0
    self.statistics = {}
  
  def __str__(self):
    return str({"url": self.url,
                "next_url": self.next_url,
                "errors": self.errors,
                "tries": self.tries,
                "statistics": self.statistics})
  
  def ParseStatisticsString(self, statistics_string):
    logging.debug("Parsing statistics from %s" % statistics_string)
    self.statistics = {}
    for line in statistics_string.splitlines():
      tuple = line.split(" ")
      if len(tuple) == 2:
        key = tuple[0]
        value = float(tuple[1])
        self.statistics[key] = value
    logging.debug("Got statistics: %s" % self.statistics)


class OperationResultHTMLParser(HTMLParser.HTMLParser):
  """HTMLParser that reads the HTML page from a Map or Reduce operation."""
  
  def handle_starttag(self, tag, attrs):
    if tag == "a":
      self.handle_start_a_tag(attrs)
    elif tag == "pre":
      self.handle_start_pre_tag(attrs)
    
  def handle_start_a_tag(self, attrs):
    """Determine the next operation's URL."""
    self.url = None
    for tuple in attrs:
      if tuple[0] == "href":
        self.url = tuple[1]
  
  def handle_start_pre_tag(self, attrs):
    """Read the statistics information from the <pre> tag."""
    self._in_pre_tag = True
  
  def handle_data(self, data):
    if hasattr(self, "_in_pre_tag") and self._in_pre_tag:
      self.statistics = data
      self._in_pre_tag = False


class MasterPageResultHTMLParser(HTMLParser.HTMLParser):
  """HTMLParser that reads the HTML page from a Master page."""

  def Init(self):
    self.urls = []
  
  def handle_starttag(self, tag, attrs):
    if tag == "a":
      self.handle_start_a_tag(attrs)
    
  def handle_start_a_tag(self, attrs):
    """Read the 'href' attribute from an 'a' tag, and add it to the list of URLs
    
    The master page for any HTTPMR operation master page lists a set of <a>
    tags, each representing the first operation of the relevant shard.  Each of
    these links should be retained and used to populate the initial set of
    operation threads.
    """ 
    logging.debug("Reading 'a' tag: %s" % attrs)
    for tuple in attrs:
      if tuple[0] == "href":
        self.urls.append(tuple[1])


class OperationThread(threading.Thread):
  """An OperationThread handles the execution and retry of an HTTP request.
  
  The OperationThread handles executing and retrying an HTTP request to a single
  Map or Reduce operation.  Once the thread has successfully completed its
  operation (successfully fetched the url assigned via #SetUrl and parsed the
  operation result page HTML), the callback set via #SetOperationCallback is
  invoked.  If there is an unrecoverable error (i.e., too many operation
  failures), the callback set via #SetUnrecoverableErrorCallback is invoked.
  """
  
  def SetOperationCallback(self, callback, **kwargs):
    """Set the callback that will be invoked when this operation is finished.
    
    args:
      callback: A callable that takes one parameter, the OperationResult
          constructed by this thread when the operation has completed, and the
          supplied keyword arguments.
      kwargs: Keyword arguments that should be passed to the callback.
    """
    self.operation_callback = callback
    self.operation_callback_kwargs = kwargs
  
  def SetUnrecoverableErrorCallback(self, callback, **kwargs):
    """Set the callback that will be invoked on unrecoverable errors.
    
    args:
      callback: A callable that takes the failed URL as its first argument, the
          unrecoverable exception as its second, and the supplied keyword
          arguments.
      kwargs: The keyword arguments that should be supplied to the callback.
    """
    self.error_callback = callback
    self.error_callback_kwargs = kwargs
  
  def SetMaxTries(self, max_tries):
    """Set the maximum number of tries that the operation can be performed.
    
    If the operation is attempted unsuccessfully more than this number of times,
    the operation is considered to fail and a TooManyTriesError is handed to the
    unrecoverable error callback.
    """
    self.max_tries = max_tries
  
  def SetUrl(self, url):
    """Specify the URL that this operation should operate on."""
    self.url = url
    self._cancel = False
  
  def run(self):
    """Fetch the URL, retry on failures, invoke error or operation callbacks."""
    assert self.url is not None
    assert self.operation_callback is not None
    assert self.error_callback is not None
    self.html = None

    logging.info("Starting operation on %s." % self.url)
    
    self.results = OperationResult()
    self.results.url = self.url
    
    try:
      if self._cancel:
        return
      self.html = self._FetchWithRetries(self.url, self.max_tries)
      logging.debug("Retrieved HTML %s" % self.html)
    except UncrecoverableOperationError, e:
      self.error_callback(self.url, e, **self.error_callback_kwargs)
    self._PopulateResults()
    if not self._cancel:
      self.operation_callback(self.results, **self.operation_callback_kwargs)
  
  def Cancel(self):
    self._cancel = True
  
  def _FetchWithRetries(self, url, max_tries):
    tries = 0
    while tries < max_tries or max_tries == INFINITE_PARAMETER_VALUE:
      try:
        tries += 1
        self.results.tries = tries
        return self._Fetch(url)
      except urllib2.HTTPError, e:
        logging.warning("HTTPError on fetch of %s: %s" % (url, str(e)))
        url = self._ReduceOperationTimeout(url)
        self.results.errors.append(e)
        self._WaitForRetry(tries)
    raise TooManyTriesError("Too many tries on URL %s" % url)
  
  def _WaitForRetry(self, tries):
    wait_time_sec = min(30 * tries, 600)
    logging.info("Sleeping for %s seconds." % wait_time_sec)
    time.sleep(wait_time_sec)
    
  def _Fetch(self, url):
    safe_url = self._GetSafeUrl(url)
    logging.debug("Fetching %s" % safe_url)
    f = urllib2.urlopen(safe_url)
    contents = f.read()
    f.close()
    return contents
  
  def _GetSafeUrl(self, url):
    parts = urlparse.urlsplit(url)
    safe_query = \
        urllib.quote(parts.query).replace("%26", "&").replace("%3D", "=")
    parts = (parts.scheme,
             parts.netloc,
             parts.path,
             safe_query,
             parts.fragment)
    return urlparse.urlunsplit(parts)

  def _ReduceOperationTimeout(self, url):
    current_timeout = None
    # TODO: Hand URL parameter parsing off to a library, here and elsewhere
    params = url.split("?")[1]
    for key_value in params.split("&"):
      (key, value) = key_value.split("=", 2)
      if key == OPERATION_TIMEOUT_SEC:
        # At this point current_timeout is a string
        current_timeout = value
    if current_timeout is not None:
      new_timeout = max(float(current_timeout) - 1,
                        MIN_OPERATION_TIMEOUT_SEC_VALUE)
      return url.replace("%s=%s" % (OPERATION_TIMEOUT_SEC, current_timeout),
                         "%s=%s" % (OPERATION_TIMEOUT_SEC, new_timeout))
    else:
      logging.warning("Could not parse the operation timeout from URL '%s', "
                      "operation retry with original timeout value." % url)
      return url
  
  def _PopulateResults(self):
    parser = OperationResultHTMLParser()
    parser.feed(self.html)
    parser.close()
    
    self.results.next_url = None
    if hasattr(parser, "url"):
      self.results.next_url = parser.url
    if hasattr(parser, "statistics"):
      self.results.ParseStatisticsString(parser.statistics)
  

class HTTPMRDriver(object):
  
  threads = []
  threads_pending = []
  
  def __init__(self,
               httpmr_base,
               max_operation_tries=-1,
               max_operations_inflight=-1):
    self.httpmr_base = httpmr_base
    self.max_operation_tries = max_operation_tries
    self.max_operations_inflight = max_operations_inflight
    self.results = []
    self.lock = threading.Lock()
    
  def Run(self):
    """Begin the Driver's Map - Reduce - Cleanup phase.
    
    It is important to use this method as the primary entry point, as it may
    be utilized in the future to precompute optimal operation parameters in the
    future.
    """
    logging.info("Beginning HTTPMR Driver Run with base URL %s" %
                 self.httpmr_base)
    self.Map()

  def _HandleUnrecoverableOperationError(self, url, error):
    logging.error("Unrecoverable error on url %s: %s; %s" %
                  (url, type(error), error))
    for thread in HTTPMRDriver.threads:
      thread.Cancel()
    logging.info("Going to cleanup.")
    self.Cleanup()
    
  def Map(self):
    self._LaunchPhase(MAP_MASTER_TASK_NAME, self._AllMapOperationsComplete)
  
  def _AllMapOperationsComplete(self):
    logging.info("Done Mapping!")
    self.Reduce()
  
  def Reduce(self):
    self._LaunchPhase(REDUCE_MASTER_TASK_NAME,
                      self._AllReduceOperationsComplete)
  
  def _AllReduceOperationsComplete(self):
    logging.info("Done Reducing!")
    self.Cleanup()
    
  def Cleanup(self):
    self._LaunchPhase(INTERMEDIATE_DATA_CLEANUP_MASTER_TASK_NAME,
                      self._AllCleanupOperationsComplete)
    
  def _AllCleanupOperationsComplete(self):
    logging.info("Done Cleaning Up!")
    logging.debug("Results: %s" % self.results)
    logging.info("Comprehensive Results: %s" % self._GetAggregateResults())
  
  def _GetAggregateResults(self):
    def AddDicts(a, b):
      sum_dict = {}
      for key in a:
        if key in b:
          sum_dict[key] = a[key] + b[key]
      return sum_dict
    return reduce(AddDicts, map(lambda result: result.statistics,
                                self.results))
  
  def _LaunchPhase(self, phase_task_name, all_operations_complete_callback):
    logging.info("Starting %s phase." % phase_task_name)
    base_urls = self._GetInitialUrls(phase_task_name)
    logging.debug("Initial URLs: %s" % ", ".join(base_urls))
    self.threads_inflight = 0
    for url in base_urls:
      thread = self._CreateOperationThread(url,
                                           all_operations_complete_callback)
      HTTPMRDriver.threads.append(thread)
      if (self.threads_inflight < self.max_operations_inflight or
          self.max_operations_inflight == INFINITE_PARAMETER_VALUE):
        self.threads_inflight += 1
        thread.start()
      else:
        HTTPMRDriver.threads_pending.append(thread)

  def _GetInitialUrls(self, task):
    url = "%s?task=%s" % (self.httpmr_base, task) 
    html = urllib2.urlopen(url).read()
    parser = MasterPageResultHTMLParser()
    parser.Init()
    parser.feed(html)
    parser.close()
    return parser.urls

  def _CreateOperationThread(self, url, all_operations_complete_callback):
    thread = OperationThread()
    thread.SetUrl(url)
    # TODO(peterdolan): Make the maximum operation tries configurable via a
    # command-line parameter
    thread.SetMaxTries(self.max_operation_tries)
    thread.SetOperationCallback(
        self._HandleThreadCompletion,
        all_operations_complete_callback=all_operations_complete_callback)
    thread.SetUnrecoverableErrorCallback(
        self._HandleUnrecoverableOperationError)
    return thread
  
  def _HandleThreadCompletion(self, results, all_operations_complete_callback):
    self.lock.acquire()
    self.threads_inflight -= 1
    
    self.results.append(results)
    if results.next_url is not None:
      logging.debug("Initializing new thread to handle %s" % results.next_url)
      thread = self._CreateOperationThread(results.next_url,
                                           all_operations_complete_callback)
      HTTPMRDriver.threads_pending.insert(0, thread)

    if HTTPMRDriver.threads_pending:
      logging.debug("Starting the next pending thread.")
      thread = self.threads_pending.pop()
      self.threads_inflight += 1
      thread.start()
    
    if not self.threads_inflight:
      logging.debug("All threads completed for this phase.")
      all_operations_complete_callback()
    self.lock.release()
  

def main():
  logging.basicConfig(level=logging.INFO,
                      format='%(asctime)s %(levelname)-8s %(message)s',
                      datefmt='%a, %d %b %Y %H:%M:%S',
                      stream=sys.stdout)
  options_parser = optparse.OptionParser()
  options_parser.add_option("-b",
                            "--httpmr_base",
                            action="store",
                            type="string",
                            dest="httpmr_base",
                            help="The base URL of the HTTPMR operation.")
  options_parser.add_option("-i",
                            "--max_operations_inflight",
                            action="store",
                            type="int",
                            dest="max_operations_inflight",
                            default=-1,
                            help="The maximum number of operations to keep "
                                + "simultaneously inflight.  -1 for inf.")
  options_parser.add_option("-f",
                            "--max_per_operation_failures",
                            action="store",
                            type="int",
                            dest="max_per_operation_failures",
                            default=-1,
                            help="The maximum number of times any given "
                                + "operation can fail before a fatal error is"
                                + " thrown.  -1 for inf.")
  options_parser.add_option("-c",
                            "--cleanup_only",
                            action="store_true",
                            dest="cleanup_only",
                            default=False,
                            help="Only execute the intermediate data cleanup "
                                + "phase.")
  (options, args) = options_parser.parse_args()
  
  driver = HTTPMRDriver(options.httpmr_base,
                        options.max_per_operation_failures,
                        options.max_operations_inflight)
  if options.cleanup_only:
    driver.Cleanup()
  else:
    driver.Run()


if __name__ == "__main__":
  main()