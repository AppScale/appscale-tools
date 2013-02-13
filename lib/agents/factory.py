from agents.ec2_agent import EC2Agent
from agents.euca_agent import EucalyptusAgent

__author__ = 'hiranya'
__email__ = 'hiranya@appscale.com'

class InfrastructureAgentFactory:
  """
  Factory implementation which can be used to instantiate concrete infrastructure
  agents.
  """

  VALID_AGENTS = ['ec2', 'euca']

  agents = {
    'ec2': EC2Agent,
    'euca': EucalyptusAgent
  }

  @classmethod
  def create_agent(cls, infrastructure):
    """
    Instantiate a new infrastructure agent.

    Args:
      infrastructure  A string indicating the type of infrastructure
                      agent to be initialized.

    Returns:
      An infrastructure agent instance that implements the BaseAgent API

    Raises:
      NameError       If the given input string does not map to any known
                      agent type.
    """
    if cls.agents.has_key(infrastructure):
      return cls.agents[infrastructure]()
    else:
      raise NameError('Unrecognized infrastructure: ' + str(infrastructure))
