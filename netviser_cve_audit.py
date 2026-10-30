#!/usr/bin/env python3
"""Backward-compatible entry point; equivalent to ``python3 -m netviser_audit``."""
import sys

from netviser_audit.cli import main

if __name__ == "__main__":
    sys.exit(main())
