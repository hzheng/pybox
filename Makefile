PROJECT_HOME :=  $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_NAME :=	$(notdir $(patsubst %/, %, $(PROJECT_HOME)))

BUILD_DIR := build
DIST_DIR := dist
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

test:
	@python setup.py test

test-report:
	@mkdir -p $(BUILD_DIR)
	@python setup.py test -v -r xml

sonar: test-report
	@sonar-runner

build:
	@python setup.py build

install-dev: check test
	@python setup.py develop

install: check test
	@python setup.py install

clean:
	@rm -rf *.egg *.egg-info $(BUILD_DIR)

distclean: clean
	@rm -rf $(DIST_DIR)

.PHONY: all $(ALL_CHECKS) check check-all test test-report sonar \
	build install-dev install clean distclean
