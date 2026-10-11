.PHONY: all test check build-rust build-c start stop clean

PYTHON ?= python

all: build-rust build-c test

build-rust:
	cd ebpf/rust-monitor && cargo build

build-c:
	@if [ -f ebpf/c-collector/Makefile ]; then \
		$(MAKE) -C ebpf/c-collector; \
	fi

test:
	$(PYTHON) -m pytest medical-agent/tests/ detector/tests/ dashboard/tests/ -v

experiments:
	$(PYTHON) experiments/runner.py

start:
	$(PYTHON) -m uvicorn dashboard.app.server:dashboard_app --host 0.0.0.0 --port 8000

clean:
	rm -rf .pytest_cache __pycache__ *.pyc
	rm -rf ebpf/c-collector/*.o ebpf/c-collector/kernelsentinel_collector
	cd ebpf/rust-monitor && cargo clean
