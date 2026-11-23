PYTHON ?= python3

.PHONY: check test bench demo clean

check:
	$(PYTHON) -m compileall -q src benchmarks examples tests skills/mcp-tool-guard/scripts scripts
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v
	PYTHONPATH=src $(PYTHON) examples/demo_live_mcp_proxy.py > /dev/null

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

bench:
	PYTHONPATH=src $(PYTHON) -m benchmarks.run_redteam

demo:
	PYTHONPATH=src $(PYTHON) examples/demo_live_mcp_proxy.py

clean:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	rm -rf .pytest_cache build dist *.egg-info .tool_guard
