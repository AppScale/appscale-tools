import unittest

from flexmock import flexmock

from appscaletools import image


class ImageTestCase(unittest.TestCase):
    def setUp(self):
        mock_images = [
                flexmock(name='appscale_cluster-1355248195-ckrintz-c827882'),
                flexmock(name='appscale_cluster-1355267915-berto-e3370ec'),
                flexmock(name='appscale_cluster-1355341616-jenkins-addd44a'),
                flexmock(name='appscale_cluster-1355342892-jenkins-6b23c32'),
                flexmock(name='appscale_cluster-1355344353-jenkins-56e28ed'),
                flexmock(name='appscale_cluster-1355349782-jenkins-2358264'),
        ]

        connection_mock = flexmock()
        (connection_mock
                .should_receive('get_all_images')
                .replace_with(lambda owners=None: mock_images))

        (flexmock(image)
                .should_receive('get_connection')
                .replace_with(lambda: connection_mock))

    def test_get_images(self):
        images = image.get_images()

        self.assertEqual(6, len(list(images)))

    def test_get_images_with_filter(self):
        images = image.get_images(regex=r'.*berto')

        self.assertEqual(1, len(list(images)))

    def test_get_images_with_filter2(self):
        # a more complex regular expression that returns all jenkins images
        # except the one listed.
        images = image.get_images(
                regex=r'appscale_cluster-.*-jenkins-(?!6b23c32)')

        self.assertEqual(3, len(list(images)))
