#!/bin/bash

# run shadow test
rm -rf shadow.data && shadow shadow.yaml

# Define the file and the string to be searched
FILE_PATH="./shadow.data/hosts/bob/bash.1001.stdout"
SEARCH_STRING="the future is now"

# Check the file for the search string
if grep -q "$SEARCH_STRING" "$FILE_PATH"; then
	echo "PASSED"
else
	echo "FAILED"
fi
