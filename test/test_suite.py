#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


import unittest


from test_appscale import TestAppScale


suite_appscale = unittest.TestLoader().loadTestsFromTestCase(TestAppScale)
all_tests = unittest.TestSuite([suite_appscale])
unittest.TextTestRunner(verbosity=2).run(all_tests)
