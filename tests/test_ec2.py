import unittest

from appscaletools.ec2 import *

class EC2TestCase(unittest.TestCase):
    def test_running_instances_parsing(self):
        matches = EC2_DESCRIBE_INSTANCES_RE.match(EC2_RUNNING_INSTANCE_SAMPLE)
        self.assertEquals('running', matches.group('running_state'))

    def test_pending_instances_parsing(self):
        matches = EC2_DESCRIBE_INSTANCES_RE.match(EC2_PENDING_INSTANCE_SAMPLE)
        self.assertEquals('pending', matches.group('running_state'))

    def test_stopped_instances_parsing(self):
        matches = EC2_DESCRIBE_INSTANCES_RE.match(EC2_STOPPED_INSTANCE_SAMPLE)
        self.assertEquals('stopped', matches.group('running_state'))
