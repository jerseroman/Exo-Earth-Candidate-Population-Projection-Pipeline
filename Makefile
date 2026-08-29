.PHONY: verify scope metadata licenses data-locks manifests tests optimized-tests public-package

verify: scope metadata licenses data-locks manifests tests optimized-tests

scope:
	python scripts/audit_repository_scope.py

metadata:
	python scripts/verify_release_metadata.py

licenses:
	python scripts/verify_license_policy.py

data-locks:
	python scripts/verify_locked_inputs.py

manifests:
	python scripts/verify_frozen_manifests.py
	python scripts/build_manifest.py --check

tests:
	python -m unittest discover -s research/bryson-joint-posterior -p "test_*.py" -v
	python -m unittest discover -s research/jj-host-export -p "test_*.py" -v
	python -m unittest discover -s research/v4-validation -p "test_*.py" -v

optimized-tests:
	python -O -m unittest discover -s research/bryson-joint-posterior -p "test_*.py" -v
	python -O -m unittest discover -s research/jj-host-export -p "test_*.py" -v
	python -O -m unittest discover -s research/v4-validation -p "test_*.py" -v

public-package: verify
	python scripts/build_public_package.py
