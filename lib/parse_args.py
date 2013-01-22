#!/usr/bin/env python


import argparse


class ParseArgs():


  def __init__(self, argv, all_flags, description):
    self.parser = argparse.ArgumentParser(description)
    self.args = self.parser.parse_args(argv)
