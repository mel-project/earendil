find ../ -type f -name '*.rs' -o -name '*.csv' | xargs cat | grep -o . | sort -u > chars.txt
pyftsubset big.ttf --text-file=chars.txt --output-file=subset.ttf