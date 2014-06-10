from agents.base_agent import AgentConfigurationException
from agents.ec2_agent import EC2Agent
from appscale_logger import AppScaleLogger
from local_state import LocalState


import boto
import os
from urlparse import urlparse

__author__ = 'dario nascimento'
__email__ = 'dario.nascimento@tecnico.ulisboa.pt'

class OpenStackAgent(EC2Agent):
    """
    OpenStack infrastructure agent which can be used to spawn and terminate
    VMs in an OpenStack based environment.
    """

    # The version of OpenStack API used to interact with Boto
    # OpenStack_API_VERSION = 'ICE-HOUSE-2014.1'

    # A list of the credentials that we require users to provide the AppScale
    # Tools with so that they can interact with Eucalyptus clouds. Right now
    # it's the same as what's needed for EC2, with an extra argument indicating
    # where the Eucalyptus deployment is located.
    REQUIRED_OPENSTACK_CREDENTIALS = list(EC2Agent.REQUIRED_EC2_CREDENTIALS) + \
                                     ['EC2_URL']

    # A list of credentials that we build our internal credential list from.
    REQUIRED_CREDENTIALS = REQUIRED_OPENSTACK_CREDENTIALS

    def describe_instances(self, parameters, pending=False):
        """
        Retrieves the list of running instances that have been instantiated using a
        particular EC2 keyname. The target keyname is read from the input parameter
        map. (Also see documentation for the BaseAgent class).

        Args:
          parameters: A dictionary containing the 'keyname' parameter.
          pending: Indicates we also want the pending instances.
        Returns:
          A tuple of the form (public_ips, private_ips, instances) where each
          member is a list.
        """
        instance_ids = []
        public_ips = []
        private_ips = []

        conn = self.open_connection(parameters)
        reservations = conn.get_all_instances()
        instances = [i for r in reservations for i in r.instances]
        for i in instances:
            if (i.state == 'running' or (pending and i.state == 'pending')) \
                    and i.key_name.startswith(parameters[self.PARAM_KEYNAME]):
                instance_ids.append(i.id)
                public_ips.append(i.public_dns_name)
                private_ips.append(i.private_dns_name)
        return public_ips, private_ips, instance_ids

    #expected url: http://192.168.2.12:8773/services/Cloud
    def open_connection(self, parameters):
        """
        Initialize a connection to the back-end OpenStack APIs.

        Args:
          parameters  A dictionary containing the 'credentials' parameter

        Returns:
          An instance of Boto EC2Connection
        """
        credentials = parameters[self.PARAM_CREDENTIALS]
        access_key = str(credentials['EC2_ACCESS_KEY'])
        secret_key = str(credentials['EC2_SECRET_KEY'])
        ec2_url = str(credentials['EC2_URL'])

        result = urlparse(ec2_url)

        if result.port is not None and result.hostname is not None and result.path is not None:
            port = result.port
        else:
            self.handle_failure('Unknown scheme in Openstack_URL: ' + result.scheme+ ' : expected like http://<controller>:8773/services/Cloud')
            return None


        #TODO: region may not be "nova"
        region = boto.ec2.regioninfo.RegionInfo(name="nova", endpoint="192.168.2.12")
        return boto.connect_ec2(aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                                is_secure=(result.scheme == 'https'),
                                region=region,
                                port=result.port,
                                path=result.path,debug=2)

