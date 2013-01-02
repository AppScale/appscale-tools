import re

from appscaletools.ec2 import get_connection

def get_images(owners=None, regex=None):
    """
    Return images found in the account.

    If a regex is provided use it to filter the results
    """

    conn = get_connection()
    owners = owners or ['self']

    filter_re = None
    if regex:
        filter_re = re.compile(regex)

    # iterate through the images and filter against the regex if one was
    # provided.
    for image in conn.get_all_images(owners=owners):
        if image.name is None:
            continue

        if filter_re and filter_re.match(image.name) is None:
            continue

        yield image
