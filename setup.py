import sys
import importlib
# import os.path as path

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

PACKAGES = find_packages()
# PROJECT_NAME = path.basename(path.dirname(path.realpath(__file__)))
main_module = importlib.import_module(PACKAGES[0])
try:
    PROJECT_NAME = main_module.__app_name__
except AttributeError:
    PROJECT_NAME = PACKAGES[0]


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
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


with open('requirements.txt') as f:
    REQUIRES = f.read().splitlines()

setup(name=PROJECT_NAME,
      version=main_module.__version__,
      author=main_module.__author__,
      author_email=main_module.__email__,
      maintainer=main_module.__maintainer__,
      url=main_module.__url__,
      description=main_module.__description__,
      license=main_module.__license__,

      packages=PACKAGES,
      install_requires=REQUIRES,
      tests_require=[
          'pytest',
          'pytest-cov',
      ],
      cmdclass={'test': PyTest})
