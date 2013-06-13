""" Provides a class that enables instantiation of infrastructure agents. """
from agents.ec2_agent import EC2Agent
from agents.euca_agent import EucalyptusAgent
try:
  # On system without GCE tools installed, the GCEAgent module will throw an 
  # ImportError.  We catch this error and redefine the 
  # InfrastructureAgentFactory class without GCEAgent so that this class will
  # work both on systems with and without the GEC tools installed.
  from agents.gce_agent import GCEAgent
  GCE_ON = True
except ImportError:
  GCE_ON = False

def get_valid_agents():
  """ Return a list of valid infrastructure agents.

  Returns:
    A list of strings, each indicating a supported infrastructure.
  """
  if GCE_ON:
    return ['ec2', 'euca', 'gce']
  else:
    return ['ec2', 'euca']

def get_agents():
  """ Return a list of valid infrastructure agents.

  Returns:
    A dict where each key is a supported infrastructure, and the associated
      value is the infrastructure agent class.
  """
  if GCE_ON:
    return {
      'ec2': EC2Agent,
      'euca': EucalyptusAgent,
      'gce': GCEAgent
    }
  else:
    return {
      'ec2': EC2Agent,
      'euca': EucalyptusAgent
    }


class InfrastructureAgentFactory:
  """
  Factory implementation which can be used to instantiate concrete
  infrastructure agents.
  """

  VALID_AGENTS = get_valid_agents()

  AGENTS = get_agents()

  @classmethod
  def create_agent(cls, infrastructure):
    """ Instantiate a new infrastructure agent.

    Args:
      infrastructure: A string indicating the type of infrastructure
        agent to be initialized.
    Returns:
      An infrastructure agent instance that implements the BaseAgent API
    Raises:
      NameError: If the given input string does not map to any known
        agent type.
    """
    if cls.AGENTS.has_key(infrastructure):
      return cls.AGENTS[infrastructure]()
    else:
      raise NameError('Unrecognized infrastructure: {0}'.format(
        infrastructure))
