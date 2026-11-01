#!/bin/sh
# DEMONSTRATION ONLY — this file exists to make the secrets gate fail on the branch demo/gate-red.
# The token below is a FAKE format (QAFAKE_ + 32 characters) invented for this repository; it is not
# a credential of any provider and grants access to nothing. See docs/gate-demo.md.
curl -s -X POST https://example.test/api/deploy \
  -H "Authorization: Bearer QAFAKE_7KDM2WPX4ZQ9VNTR6HLB3YJC8SAEFG5U" \
  -d "status=$1"
