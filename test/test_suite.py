#!/usr/bin/env python
# Programmer: Chris Bunch, Brian Drawert

import sys
import unittest


# imports for appscale executable tests
from test_appscale import TestAppScale
from test_appscale_describe_instances import TestAppScaleDescribeInstances
from test_appscale_add_instances import TestAppScaleAddInstances
from test_appscale_add_keypair import TestAppScaleAddKeypair
from test_appscale_gather_logs import TestAppScaleGatherLogs
from test_appscale_get_property import TestAppScaleGetProperty
from test_appscale_relocate_app import TestAppScaleRelocateApp
from test_appscale_remove_app import TestAppScaleRemoveApp
from test_appscale_reset_pwd import TestAppScaleResetPassword
from test_appscale_run_instances import TestAppScaleRunInstances
from test_appscale_upload_app import TestAppScaleUploadApp
from test_appscale_terminate_instances import TestAppScaleTerminateInstances


# imports for appscale library tests
from test_appscale_logger import TestAppScaleLogger
from test_factory import TestFactory
from test_local_state import TestLocalState
from test_node_layout import TestNodeLayout
from test_parse_args import TestParseArgs
from test_remote_helper import TestRemoteHelper
from test_version_helper import TestVersionHelper


test_cases = [TestAppScale, TestAppScaleAddInstances, TestAppScaleAddKeypair,
  TestAppScaleDescribeInstances, TestAppScaleGatherLogs, TestAppScaleGetProperty,
  TestAppScaleRelocateApp,TestAppScaleRemoveApp,
  TestAppScaleResetPassword, TestAppScaleRunInstances,
  TestAppScaleTerminateInstances, TestAppScaleUploadApp, TestAppScaleLogger,
  TestFactory, TestLocalState, TestNodeLayout, TestParseArgs, TestRemoteHelper,
  TestVersionHelper]

test_case_names = []
for cls in test_cases:
  test_case_names.append(str(cls.__name__))

appscale_test_suite = unittest.TestSuite()
if len(sys.argv) > 1:
  if sys.argv[1] in test_case_names:
    print "only running test "+sys.argv[1]
    run_test_cases = [sys.argv[1]]
  else:
    print "ERROR: unknown test "+sys.argv[1]
    print "Options are: "+", ".join(test_case_names)
    sys.exit(1)
else:
  run_test_cases = test_case_names

for test_class, test_name in zip(test_cases, test_case_names):
  if test_name in run_test_cases:
    tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
    appscale_test_suite.addTests(tests)

all_tests = unittest.TestSuite([appscale_test_suite])
unittest.TextTestRunner(verbosity=2).run(all_tests)
