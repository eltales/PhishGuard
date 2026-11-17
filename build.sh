#!/usr/bin/env bash
# Builds phishguard.xpi for installation in Thunderbird.
set -euo pipefail
cd "$(dirname "$0")"
rm -f phishguard.xpi
zip -r phishguard.xpi manifest.json src
echo "Built: phishguard.xpi"
