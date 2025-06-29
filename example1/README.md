Step-by-step insruction:

```bash
docker build -t my-zokrates .
docker run -it --rm my-zokrates bash
python3 sbom_pre.py > sbom_hashes.txt
zokrates compile -i example1.zok
zokrates setup
./verify_vuln.sh
