import os
import glob
import shutil
import json

import nvd


PLUGIN_URL_PREFIXES = (
    "https://wordpress.org/plugins/",
    "https://plugins.trac.wordpress.org/",
    "https://plugins.svn.wordpress.org/"
)


if __name__ == "__main__":
    for nvd_entry_filepath in glob.iglob("../unsorted/CVE-*.json"):
        with open(nvd_entry_filepath) as fin:
            nvd_entry = json.load(fin)

        is_plugin = False
        for ref in nvd.extract_references(nvd_entry):
            if "wordpress" in ref["url"]:
                for prefix in PLUGIN_URL_PREFIXES:
                    if ref["url"].startswith(prefix):
                        is_plugin = True
                        break

        if not is_plugin:
            continue

        fname = os.path.basename(nvd_entry_filepath)
        fdest = f"../sorted/plugins/{fname}"
        shutil.move(nvd_entry_filepath, fdest)
