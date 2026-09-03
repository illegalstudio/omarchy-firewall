.PHONY: check release test validate

NODE ?= node
OMARCHY ?= omarchy
PERL ?= perl
PYTHON ?= python3

check: validate test

validate:
	@$(PYTHON) -m json.tool manifest.json >/dev/null
	@$(OMARCHY) plugin validate .

test:
	@$(NODE) test/run.js
	@$(PERL) test/read-state.t
	@$(PERL) test/run-action.t

release:
	@scripts/release.sh
