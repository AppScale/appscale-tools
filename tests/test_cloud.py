import unittest

from flexmock import flexmock

from appscaletools import cloud


class CloudTestCase(unittest.TestCase):
    def setUp(self):
        self.name = 'foo'
        self.cloud = cloud.Cloud(self.name)

    def test_terminate(self):
        mock = flexmock(self.cloud)
        mock.should_receive('terminate_instances').once()
        mock.should_receive('remove_key_pair').once()
        mock.should_receive('remove_group').once()

        self.cloud.terminate()

    def test_terminate_instances(self):

        # create two instances, one that matches the name 'foo' and one that does not
        instance1 = flexmock(key_name='foo')
        instance1.should_receive('terminate').once()

        instance2 = flexmock(key_name='bar')

        # create a reservation with the two instances above
        reservation_mock = flexmock(instances=[instance1, instance2])

        (flexmock(self.cloud.connection)
                .should_receive('get_all_instances')
                .replace_with(lambda: [reservation_mock]))

        self.cloud.terminate_instances()

    def test_remove_group(self):
        # create two groups, one that matches the name 'foo' and one that does not
        group1 = flexmock(name='foo')
        group1.should_receive('delete').once()

        group2 = flexmock(name='bar')

        (flexmock(self.cloud.connection)
                .should_receive('get_all_security_groups')
                .replace_with(lambda: [group1, group2]))

        self.cloud.remove_group()

    def test_remove_key_pair(self):
        # create two groups, one that matches the name 'foo' and one that does not
        keypair1 = flexmock(name='foo')
        keypair1.should_receive('delete').once()

        keypair2 = flexmock(name='bar')

        (flexmock(self.cloud.connection)
                .should_receive('get_all_key_pairs')
                .replace_with(lambda: [keypair1, keypair2]))

        self.cloud.remove_key_pair()
