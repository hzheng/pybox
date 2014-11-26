import sys
import os.path as path

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

PROJECT_NAME = path.basename(path.dirname(path.realpath(__file__)))
PROJECT_VERSION = "0.1"
PACKAGES = find_packages()


class PyTest(TestCommand):
    user_options = [
        ('test-verbose', 'v', "test verbosely"),
        ('cov-report=', 'r', "coverage report format")
    ]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = ['--cov={}'.format(p) for p in PACKAGES]
        self.cov_report = []
        self.test_verbose = False

    def finalize_options(self):
        TestCommand.finalize_options(self)
        if self.cov_report:
            self.pytest_args.append("--cov-report=" + self.cov_report)
        if self.test_verbose:
            self.pytest_args.append("--verbose")
        self.test_suite = True
        # avoid NoneType
        self.test_args = []

    def run_tests(self):
        import pytest
        print self.pytest_args
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


with open('requirements.txt') as f:
    requires = f.read().splitlines()

setup(name=PROJECT_NAME,
      version=PROJECT_VERSION,
      packages=PACKAGES,

      install_requires=requires,

      tests_require=[
          'pytest',
          'pytest-cov',
      ],
      cmdclass={'test': PyTest},

      author='Hui Zheng',
      description='a Python API/client that manipulates files on box.com'
      )
