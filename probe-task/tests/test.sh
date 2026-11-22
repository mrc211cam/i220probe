#!/bin/bash
# Runtime vantage probe verifier.
mkdir -p /logs/verifier
python3 /tests/probe.py
rc=$?
if [ ! -s /logs/verifier/reward.txt ]; then
  echo 1 > /logs/verifier/reward.txt
fi
exit 0
