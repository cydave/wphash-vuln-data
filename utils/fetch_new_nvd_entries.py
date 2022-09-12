import gzip
import json

import requests

import nvd


if __name__ == "__main__":
    with open("./data/seen_cves.txt") as fin:
        existing_cves = {line.strip() for line in fin}

    response = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz")
    raw = json.loads(gzip.decompress(response.content))
    for cve_entry in raw["CVE_Items"]:
        cve_id = nvd.extract_cve_id(cve_entry)
        if cve_id in existing_cves:
            continue

        str_entry = json.dumps(cve_entry)
        if "wordpress" not in str_entry.lower():
            continue

        unsorted_filepath = f"../unsorted/{cve_id}.json"
        with open(unsorted_filepath, "w") as fout:
            json.dump(cve_entry, fout, indent=2)
            print(f"[NEW]: {unsorted_filepath}")
