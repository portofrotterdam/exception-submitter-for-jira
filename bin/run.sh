#!/bin/bash
echo ""
echo "Running Python Exception Submitter Service"
echo ""

BASE_DIR=`dirname $0`

(cd ${BASE_DIR}/../ && python3 main.py) # >/dev/null 2>&1)

exit 0
