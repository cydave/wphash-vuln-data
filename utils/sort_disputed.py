import os
import glob
import shutil
import json

import nvd


if __name__ == "__main__":
    for nvd_entry_filepath in glob.iglob("../unsorted/CVE-*.json"):
        with open(nvd_entry_filepath) as fin:
            nvd_entry = json.load(fin)

        description = nvd.extract_details(nvd_entry)
        if description is None:
            continue

        if "** DISPUTED **" not in description:
            continue

        fname = os.path.basename(nvd_entry_filepath)
        fdest = f"../sorted/excluded/{fname}"
        shutil.move(nvd_entry_filepath, fdest)
        print(f"Moved disputed item: {nvd_entry_filepath} -> {fdest}")
