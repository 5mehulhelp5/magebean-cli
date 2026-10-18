#!/usr/bin/env bash
set -u
passed=0
failed=0
for test_file in tests/*Test.php; do
    if php "$test_file" > /tmp/magebean-last-test.log 2>&1; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        echo "$test_file"
        cat /tmp/magebean-last-test.log
    fi
done
echo "Passed: $passed; failed: $failed"
test "$failed" -eq 0
