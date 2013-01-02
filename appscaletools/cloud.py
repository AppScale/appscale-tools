"""
AppScale Cloud module.
"""

import logging

from appscaletools.ec2 import get_connection

class Cloud(object):
    """
    Class to manipulate a deployed cloud.

    Currently used to terminate a cloud and remove keys and security groups.
    """

    def __init__(self, name, logger=None):
        self.connection = get_connection()
        self.name = name

        self.logger = logger or logging.getLogger('Cloud')

    def remove_group(self):
        """
        Remove the group with the specified name
        """

        self.logger.debug('Removing security group')

        for group in self.connection.get_all_security_groups():
            if group.name != self.name:
                continue

            self.logger.info('Delete {0}'.format(group))
            group.delete()

    def remove_key_pair(self):
        """
        Remove the key_pair with the specified name
        """
        self.logger.debug('Removing key pair')

        for key_pair in self.connection.get_all_key_pairs():
            if key_pair.name != self.name:
                continue

            self.logger.info('Delete {0}'.format(key_pair))
            key_pair.delete()

    def terminate(self):
        """
        Terminate a cloud and clean up ancillary objects.

        Will terminate any instances, keys, and security groups with the given
        name.
        """

        self.terminate_instances()
        self.remove_key_pair()
        self.remove_group()

    def terminate_instances(self):
        """
        Terminate any instance with the given name
        """

        self.logger.debug('Terminating instances')

        for reservation in self.connection.get_all_instances():
            for instance in reservation.instances:
                if instance.key_name != self.name:
                    continue

                self.logger.info('Terminate {0}'.format(instance))
                instance.terminate()
