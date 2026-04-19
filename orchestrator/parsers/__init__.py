# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Capture-tool parsers.

Each parser is a pure function over a fixture file. Output is plain dicts; the
STIX builder consumes them separately so we can unit-test parsers without any
STIX/database dependency.
"""

from .procmon import ProcmonEvent, parse_procmon_csv
from .regshot import RegistryDelta, parse_regshot_diff
from .pcap import PcapFlow, parse_pcap

__all__ = [
    "ProcmonEvent",
    "parse_procmon_csv",
    "RegistryDelta",
    "parse_regshot_diff",
    "PcapFlow",
    "parse_pcap",
]
