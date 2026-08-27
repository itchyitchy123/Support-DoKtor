.PHONY: setup format lint dependencies type test coverage build check clean

PYTHON ?= python3

setup:
	$(PYTHON) -m pip install -e '.[dev]'

format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

lint:
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .

dependencies:
	$(PYTHON) -m pip check

type:
	$(PYTHON) -m mypy src

test:
	$(PYTHON) -m unittest discover -s tests -v

coverage:
	$(PYTHON) -m coverage run -m unittest discover -s tests
	$(PYTHON) -m coverage report

build:
	$(PYTHON) -m build

check: lint dependencies type coverage build

clean:
	$(PYTHON) -m coverage erase
