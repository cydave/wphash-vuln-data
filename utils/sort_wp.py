import os
import glob
import shutil
import json

import nvd


if __name__ == "__main__":
    for nvd_entry_filepath in glob.iglob("../unsorted/CVE-*.json"):
        with open(nvd_entry_filepath) as fin:
            nvd_entry = json.load(fin)
            entries = nvd.extract_cpes(nvd_entry)
            allwp = True
            for entry in entries:
                if not entry.startswith("cpe:2.3:a:wordpress:wordpress:"):
                    allwp = False
                    break
            if allwp:
                fname = os.path.basename(nvd_entry_filepath)
                fdest = f"../sorted/wordpress-core/{fname}"
                shutil.move(nvd_entry_filepath, fdest)
