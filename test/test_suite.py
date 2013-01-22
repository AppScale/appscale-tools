#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


import unittest


from test_appscale import TestAppScale
from test_appscale_run_instances import TestAppScaleRunInstances
from test_parse_args import TestParseArgs


test_cases = [TestAppScale, TestAppScaleRunInstances, TestParseArgs]
appscale_test_suite = unittest.TestSuite()
for test_class in test_cases:
  tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
  appscale_test_suite.addTests(tests)

all_tests = unittest.TestSuite([appscale_test_suite])
unittest.TextTestRunner(verbosity=2).run(all_tests)
