#!/bin/bash
# verify_vuln.sh 

i=0
while read -r line; do
  ((i++))
  echo "@ Component #$i:"
  
  if echo "$line" | zokrates compute-witness --stdin > /dev/null 2>&1; then
    echo "[Oops] Vulnerability MATCHED: Component #$i is VULNERABLE!"
  else
    echo "Safe: Component #$i does NOT match known vulnerable hash."
  fi
done < sbom_hashes.txt
