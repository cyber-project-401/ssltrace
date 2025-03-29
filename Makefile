.PHONY: help setup install-bcc check-bcc run-container clean

# Optional: override the container name
CONTAINER ?= sslclient

help:
	@echo "Available targets:"
	@echo "  make setup              - Ensure BCC is installed and usable"
	@echo "  make install-bcc        - Install BCC system-wide (tools + Python bindings)"
	@echo "  make check-bcc          - Check if 'bcc' Python module is accessible"
	@echo "  make run-container      - Trace SSL in a container by name (default: $(CONTAINER))"
	@echo "  make clean              - Remove __pycache__ and .pyc files"

setup:
	@echo "🔧 Checking if 'bcc' is available..."
	@if python3 -c "import bcc" 2>/dev/null; then \
		echo "✅ bcc Python module is already available."; \
	else \
		echo "❌ bcc not found. Installing..."; \
		$(MAKE) install-bcc; \
		$(MAKE) check-bcc; \
	fi

install-bcc:
	sudo apt update
	sudo apt install -y bpfcc-tools python3-bcc linux-headers-$(shell uname -r)

check-bcc:
	@echo "🔍 Verifying BCC availability..."
	@python3 -c "import bcc; print('✅ bcc is available:', bcc.__file__)" || \
	(echo '❌ bcc still not found! Make sure apt installed it.' && exit 1)

run: setup
	sudo python3 ssltrace.py

clean:
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type f -name "*.pyc" -delete

