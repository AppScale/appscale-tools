from ec2_agent import EC2Agent
from euca_agent import EucalyptusAgent
from gce_agent import GCEAgent
from openstack_agent import OpenStackAgent

try:
  from appscale.custom_exceptions import UnknownInfrastructureException
except ImportError:
  # If the module is not installed, the lib directory might be on the path.
  from custom_exceptions import UnknownInfrastructureException

__author__ = 'hiranya'
__email__ = 'hiranya@appscale.com'


class InfrastructureAgentFactory:
  """ Factory implementation which can be used to instantiate infrastructure
  agents. """


  # A set containing each of the cloud infrastructures that AppScale can
  # deploy over.
  VALID_AGENTS = ('ec2', 'euca', 'gce','openstack')


  # A dict that maps each VALID_AGENT above to the class that implements
  # support for it in AppScale.
  agents = {
    'ec2': EC2Agent,
    'euca': EucalyptusAgent,
    'gce': GCEAgent,
    'openstack': OpenStackAgent
  }


  @classmethod
  def create_agent(cls, infrastructure):
    """
    Instantiate a new infrastructure agent.

    Args:
      infrastructure: A string indicating the type of infrastructure
        agent to be initialized.
    Returns:
      An infrastructure agent instance that implements the BaseAgent API
    Raises:
      UnknownInfrastructureException: If the infrastructure given is not one
        that we support.
    """
    if cls.agents.has_key(infrastructure):
      return cls.agents[infrastructure]()
    else:
      raise UnknownInfrastructureException('Unrecognized infrastructure: {0}' \
        .format(infrastructure))
