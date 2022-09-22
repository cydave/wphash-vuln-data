import os
import glob
import shutil
import json

import nvd


if __name__ == "__main__":
    for nvd_entry_filepath in glob.iglob("../unsorted/CVE-*.json"):
        with open(nvd_entry_filepath) as fin:
            nvd_entry = json.load(fin)

        is_plugin = False
        for ref in nvd.extract_references(nvd_entry):
            if ref["url"].startswith("https://wordpress.org/plugins/"):
                is_plugin = True
                break

        if not is_plugin:
            continue

        fname = os.path.basename(nvd_entry_filepath)
        fdest = f"../sorted/plugins/{fname}"
        shutil.move(nvd_entry_filepath, fdest)
