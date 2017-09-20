import requests

from appscale_logger import AppScaleLogger
from local_state import LocalState
from render_helper import print_table
from requests.packages.urllib3.exceptions import InsecureRequestWarning


APPS_PATH = "/v1/apps"
SERVICES_PATH = "/v1/apps/{app_id}/services"
VERSIONS_PATH = "/v1/apps/{app_id}/services/{service_id}/versions"


def get_response(host, secret, path):
  """
  Returns a request's response.

  Args:
    host: A string specifying the login host.
    secret: A string specifying the secret key.
    path: A string specifying a path to request
      to apps, services or versions node.
  Returns:
    A dict specifying information from the requested node.
  """
  headers = {
    'Appscale-Secret': secret
  }

  administration_port = "17441"
  url = "https://{host}:{port}{path}".format(
    host=host,
    port=administration_port,
    path=path
  )

  resp = requests.get(
    url=url,
    headers=headers,
    verify=False
  )

  resp.raise_for_status()
  return resp.json()


def sort_services(services):
  """
  Sorts services by project ID, service ID, version and ports.

  Args:
    services: A list specifying the services information.
  Returns:
    A list specifying the sorted services information.
  """
  return sorted(services,
                key=lambda app: (app[0], app[1], app[2], app[3], app[4]))


def obtain_services_info(host, secret, app):
  """
  Obtains services information to specify app ID.

  Args:
    host: A string specifying the login host.
    secret: A string specifying the secret key.
    app: A string specifying the app ID.
  Returns:
    A list specifying app, service and version information.
  """
  app_id = app["id"]
  services = get_response(
    host=host, secret=secret,
    path=SERVICES_PATH.format(app_id=app_id))

  for service in services["services"]:
    service_id = service["id"]
    versions = get_response(
      host=host, secret=secret,
      path=VERSIONS_PATH.format(app_id=app_id, service_id=service_id))

    for version in versions["versions"]:
      return [
        app_id,
        service_id,
        version["id"],
        version["http_port"],
        version["https_port"]
      ]


def print_services(options):
  """
  Prints an information about project's services.

  Args:
    options: A Namespace that has fields for each parameter that can be
      passed in via the command-line interface.
  """
  login_host = LocalState.get_login_host(keyname=options.keyname)
  secret = LocalState.get_secret_key(keyname=options.keyname)

  table_name = "SERVICES INFO"
  headers = ["APPLICATION", "SERVICE", "VERSION", "HTTP", "HTTPS"]
  services_info = []

  try:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    if options.appname:
      app = get_response(
        host=login_host, secret=secret,
        path="{apps_path}/{app}".format(
          apps_path=APPS_PATH, app=options.appname))

      services_info.append(
        obtain_services_info(host=login_host, secret=secret, app=app))

    else:
      apps = get_response(host=login_host, secret=secret, path=APPS_PATH)

      for app in apps["apps"]:
        services_info.append(
          obtain_services_info(host=login_host, secret=secret, app=app))

  except requests.HTTPError as e:
    AppScaleLogger.warn("Failed to get services info.")
    AppScaleLogger.warn(e)

  print_table(
    table_name=table_name,
    headers=headers,
    data=sort_services(services_info)
  )
