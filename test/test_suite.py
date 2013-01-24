#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


import unittest


# imports for appscale executable tests
from test_appscale import TestAppScale
from test_appscale_run_instances import TestAppScaleRunInstances


# imports for appscale library tests
from test_appscale_logger import TestAppScaleLogger
from test_local_state import TestLocalState
from test_node_layout import TestNodeLayout
from test_parse_args import TestParseArgs


test_cases = [TestAppScale, TestAppScaleRunInstances,
  TestAppScaleLogger, TestLocalState, TestNodeLayout, TestParseArgs]
appscale_test_suite = unittest.TestSuite()
for test_class in test_cases:
  tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
  appscale_test_suite.addTests(tests)

all_tests = unittest.TestSuite([appscale_test_suite])
unittest.TextTestRunner(verbosity=2).run(all_tests)
