#!/usr/bin/env python3
"""Inert disposable-runner sentinel: any execution is a qualification failure."""

from pathlib import Path


marker = Path(__file__).with_name("UNEXPECTED_COUNCIL_SERVER_START")
marker.write_bytes(b"unexpected Council adapter start\n")
raise SystemExit(97)
