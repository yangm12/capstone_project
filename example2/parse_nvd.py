import json
import hashlib
import csv

# ======== Configuration  ========
NVD_JSON_FILE = "nvdcve-1.1-2010.json"  # Input file name
CSV_OUTPUT_FILE = "nvd_2010_vuln_components.csv"  # Output CSV file name
SKIPPED_RANGE_FILE = "skipped_version_ranges.csv"  # Version range output
# ==========================

def extract_vulnerable_cpes_from_node(node):
    entries = []
    if "cpe_match" in node:
        for cpe_match in node["cpe_match"]:
            if cpe_match.get("vulnerable", False):
                entries.append(cpe_match)
    # Recursive child node
    for child in node.get("children", []):
        entries.extend(extract_vulnerable_cpes_from_node(child))
    return entries


def extract_vulnerable_components(nvd_json_path):
    with open(nvd_json_path, "r") as f:
        data = json.load(f)

    results = []
    skipped_count = 0  
    skipped_version_ranges = []

    for item in data.get("CVE_Items", []):
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        nodes = item.get("configurations", {}).get("nodes", [])

        for node in nodes:
            for cpe_match in extract_vulnerable_cpes_from_node(node):
                cpe_uri = cpe_match.get("cpe23Uri", "")
                parts = cpe_uri.split(":")
                if len(parts) >= 7:
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5]
                    update = parts[6] if parts[6] != "*" else ""
                    
                    if version == "*" and (
                        "versionStartIncluding" in cpe_match or "versionStartExcluding" in cpe_match or
                        "versionEndExcluding" in cpe_match or "versionEndIncluding" in cpe_match
                    ):
                        # Construct range strings
                        start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                        end = cpe_match.get("versionEndExcluding") or cpe_match.get("versionEndIncluding")
    
                        range_str = ""
                        if start and end:
                            range_str = f"{start} -<{end}" if "versionEndExcluding" in cpe_match else f"{start} -<={end}"
                        elif start:
                            range_str = f">={start}" if "versionStartIncluding" in cpe_match else f">{start}"
                        elif end:
                            range_str = f"<={end}" if "versionEndIncluding" in cpe_match else f"<{end}"
    
                        skipped_version_ranges.append([cve_id, vendor, product, range_str])
                        skipped_count += 1
                        continue

                    
                    
                    full_version = f"{version}-{update}" if update else version

                    if product and version and version != "*": 
                        full_id = f"{product}:{full_version}"
                        sha256 = hashlib.sha256(full_id.encode("utf-8")).hexdigest()
                        results.append([cve_id, vendor, product, full_version, sha256])
                
                    else:
                        skipped_count += 1  # malformed cpe_uri
    return results, skipped_count, skipped_version_ranges

def save_to_csv(rows, output_file, header):
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

if __name__ == "__main__":
    print(f"1. READ {NVD_JSON_FILE} ...")
    parsed_rows, skipped, skipped_ranges = extract_vulnerable_components(NVD_JSON_FILE)
    print(f"2. GET {len(parsed_rows)} VALID COMPONENTS")
    print(f"3. SKIPPED {skipped} INVALID COMPONENTS")

    print(f"4. VALID COMPONENTS SAVED TO {CSV_OUTPUT_FILE} ...")
    save_to_csv(parsed_rows, CSV_OUTPUT_FILE, ["cve_id", "vendor", "product", "version", "sha256"])
    print(f"5. INVALID COMPONENTS SAVED TO {SKIPPED_RANGE_FILE} ...")
    save_to_csv(skipped_ranges, SKIPPED_RANGE_FILE, ["cve_id", "vendor", "product", "version_range"])
    print("6. DONE")
