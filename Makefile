.PHONY: verify dependencies workflows scope metadata licenses data-locks manifests tests optimized-tests public-package

PYTHON ?= python

verify: dependencies workflows scope metadata licenses data-locks manifests tests optimized-tests

dependencies:
	$(PYTHON) scripts/verify_dependency_lock.py
	$(PYTHON) -m pip check

workflows:
	$(PYTHON) scripts/verify_workflow_security.py

scope:
	$(PYTHON) scripts/audit_repository_scope.py

metadata:
	$(PYTHON) scripts/verify_release_metadata.py

licenses:
	$(PYTHON) scripts/verify_license_policy.py

data-locks:
	$(PYTHON) scripts/verify_locked_inputs.py

manifests:
	$(PYTHON) scripts/verify_frozen_manifests.py
	$(PYTHON) scripts/build_manifest.py --check

tests:
	$(PYTHON) -m unittest discover -s research/bryson-joint-posterior -p "test_*.py" -v
	$(PYTHON) -m unittest discover -s research/jj-host-export -p "test_*.py" -v
	$(PYTHON) -m unittest discover -s research/v4-validation -p "test_*.py" -v

optimized-tests:
	$(PYTHON) -O -m unittest discover -s research/bryson-joint-posterior -p "test_*.py" -v
	$(PYTHON) -O -m unittest discover -s research/jj-host-export -p "test_*.py" -v
	$(PYTHON) -O -m unittest discover -s research/v4-validation -p "test_*.py" -v

public-package: verify
	$(PYTHON) scripts/build_public_package.py
