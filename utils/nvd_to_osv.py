import sys
import argparse
import hashlib
import json

import requests

import nvd


def make_osv_id(slug: str, cve_id: str) -> str:
    """Create a WPHSH identifier."""
    sh = hashlib.sha256(slug.encode()).hexdigest()[:12]
    ch = hashlib.sha256(cve_id.encode()).hexdigest()[:12]
    return f"WPHSH-{sh}-{ch}"


def load_nvd_entry(filepath):
    with open(filepath) as fin:
        return json.load(fin)


def fetch_plugin_info(slug: str):
    response = requests.get(f"https://wpha.sh/api/plugins/{slug}")
    if response.status_code != 200:
        return None
    raw_plugin = response.json()
    versions = [v for v in raw_plugin["versions"] if v["seen_date"]]
    sorted_versions = sorted(versions, key=lambda v: v["seen_date"], reverse=True)
    raw_plugin["versions"] = [v["version"] for v in sorted_versions]
    return raw_plugin


def main(args):
    nvd_entry = load_nvd_entry(args.nvd_file)
    plugin = fetch_plugin_info(args.slug)
    if plugin is None:
        print("Error: Unable to find plugin on wpha.sh...")
        exit(1)

    raw_osv = {
        "id": make_osv_id(args.slug.strip(), args.cve.upper()),
        "modified": nvd.extract_modified(nvd_entry),
        "published": nvd.extract_published(nvd_entry),
        "aliases": nvd.extract_aliases(nvd_entry),
        "summary": "FIXME",
        "details": nvd.extract_details(nvd_entry),
        "severity": nvd.extract_severity(nvd_entry),
        "affected": [
            {
                "package": {
                    "ecosystem": "wordpress-plugin",
                    "name": args.slug
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "repo": f"https://plugins.svn.wordpress.org/{args.slug}",
                        "events": [
                            {
                                "introduced": "0"
                            },
                            {
                                "fixed": "TODO"
                            }
                        ]
                    }
                ],
                "versions": plugin["versions"]
            }
        ],
        "references": nvd.extract_references(nvd_entry),
        "database_specific": {
            "slug": args.slug,
            "name": plugin["name"],
            "cwe_ids": nvd.extract_cwe_ids(nvd_entry)
        }
    }
    if raw_osv["severity"] is None:
        del raw_osv["severity"]
    print(json.dumps(raw_osv, indent=4))



if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--cve", required=True)
    ap.add_argument("-s", "--slug", required=True)
    ap.add_argument("-f", "--nvd-file", required=True)
    args = ap.parse_args()
    main(args)
