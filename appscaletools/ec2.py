"""
EC2 specific variables and helpers.
"""

import re

import sh

from boto.ec2.connection import EC2Connection

EC2_DESCRIBE_INSTANCES_RE = re.compile((
    r'INSTANCE\s+(?P<instance_id>\S+)\s+'
    r'(?P<ami_id>\S+)\s+'
    r'(?P<ec2_hostname>\S+amazonaws\.com)?\s*'
    r'(?P<ec2_private_hostname>\S+\.internal)?\s*'
    r'(?P<running_state>\S+).*'
))
EC2_DESCRIBE_INSTANCES = sh.Command('ec2-describe-instances')

EC2_RUN_INSTANCES_RE = re.compile(r'INSTANCE\s+(?P<instance_id>\S+).*')
EC2_RUNNING_STATE = 'running'
EC2_STOPPED_STATE = 'stopped'

# -- samples for testing and perusal -- #

EC2_RUNNING_INSTANCE_SAMPLE = (
    'INSTANCE    i-37b8b548  ami-1db20274 ec2-23-22-46-174.compute-1.amazonaws.com    ip-10-4-54-135.ec2.internal '
    'running  berto   0       m1.small    2012-12-01T02:28:30+0000    us-east-1c  aki-427d952  '
    'monitoring-disabled 23.22.46.174    10.4.54.135         instance-store'
)

EC2_PENDING_INSTANCE_SAMPLE = (
    'INSTANCE  i-91e9e4ee  ami-1db20274            pending berto   0       m1.small    2012-12-01T01:55:17+0000 '
    'us-east-1d  aki-427d952b            monitoring-disabled             '
)

EC2_STOPPED_INSTANCE_SAMPLE = (
    'INSTANCE  i-0f333a70  ami-c7b202ae            stopped berto   0       m1.small    2012-12-01T10:21:05+0000    '
    'us-east-1c  aki-427d952b            monitoring-disabled                 ebs     '
)

EC2_EBS_RUNNING_INSTANCE_SAMPLE = (
    'INSTANCE  i-2d92c652  ami-c7b202ae    ec2-54-235-243-239.compute-1.amazonaws.com  ip-10-62-97-8.ec2.internal  '
    'running berto   0       m1.small    2012-11-26T19:55:18+0000    us-east-1d  aki-427d952b            '
    'monitoring-disabled 54.235.243.239  10.62.97.8          ebs     '
)

CONNECTIONS = []
def get_connection():
    """
    Return a Boto EC2Connection instance.

    This will cache the connection and return it on subsequent requests.
    """

    if CONNECTIONS:
        return CONNECTIONS[0]

    connection = EC2Connection()

    CONNECTIONS.append(connection)

    return connection
