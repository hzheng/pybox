PROJECT_HOME :=  $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_NAME :=	$(notdir $(patsubst %/, %, $(PROJECT_HOME)))

BUILD_DIR := build
DIST_DIR := dist
TEST_DIR := tests
TEST_FILES := $(wildcard $(TEST_DIR)/*.py)
TEST_TARGETS := $(TEST_FILES:$(TEST_DIR)/%.py=%)
BASIC_CHECKS := pep8 pyflakes
ALL_CHECKS := $(BASIC_CHECKS) pylint pychecker

all: check test

$(ALL_CHECKS):
	@if command -v $@ &> /dev/null; \
	 then \
	 	echo checking by $@...; \
    	find $(PROJECT_NAME) -name \*.py | xargs $@; \
	 else \
    	echo $@ is not installed, please run \"pip install $@\" first; \
    	exit 1; \
     fi;


check: $(BASIC_CHECKS)

check-all: $(ALL_CHECKS)

$(TEST_TARGETS): % : $(TEST_DIR)/%.py
	@py.test -svv $<

test: $(TEST_TARGETS)

test-term:
	@python setup.py test -v -r term

test-xml:
	@mkdir -p $(BUILD_DIR)
	@python setup.py test -v -r xml

sonar: test-xml
	@sonar-runner

build:
	@python setup.py build

install-dev:
	@python setup.py develop

install:
	@python setup.py install

clean:
	@rm -rf *.egg *.egg-info $(BUILD_DIR)

distclean: clean
	@rm -rf $(DIST_DIR)

realclean: distclean
	@find . -name __pycache__ |xargs rm -rf
	@find . -name \*.pyc | xargs rm -f

.PHONY: all $(TEST_TARGETS) $(ALL_CHECKS) check check-all test test-term \
	test-xml sonar build install-dev install clean distclean realclean
