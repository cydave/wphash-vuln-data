import os
import glob
import json



if __name__ == "__main__":
    seen = []
    # Extract CVE identiffiers from OSV files.
    for f in glob.iglob("../advisories/*.json"):
        with open(f) as fin:
            raw_advisory = json.load(fin)
            cve_id = raw_advisory["aliases"][0]
            seen.append(cve_id)

    # Extract CVE identifiers from unprocessed files.
    for g in ("../unsorted/*.json", "../sorted/*/*.json"):
        for f in glob.iglob(g):
            filename = os.path.basename(f)
            if not filename.startswith("CVE-"):
                continue
            cve_id = filename.split(".")[0]
            seen.append(cve_id)


    with open("./data/seen_cves.txt", "w") as fout:
        fout.write("\n".join(sorted(seen)))
