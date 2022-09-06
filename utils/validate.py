import sys
import glob
import json
from typing import Tuple, Optional

import jsonschema

with open("./schema.json") as fin:
    JSON_SCHEMA = json.load(fin)


def validate_file(vuln_file: str) -> Tuple[bool, Optional[Exception]]:
    with open(vuln_file) as fin:
        raw_vuln = json.load(fin)
        try:
            jsonschema.validate(raw_vuln, schema=JSON_SCHEMA)
            return True, None
        except jsonschema.ValidationError as e:
            return False, e


def print_validity(is_valid: bool, exc: Optional[Exception], vuln_file: str):
    message =     f"[  OK ] {vuln_file}"
    if not is_valid:
        message = f"[ ERR ] {vuln_file}"
    print(message)
    if exc:
        print(exc)
        print()


def validate_all():
    for vuln_file in glob.iglob("../advisories/*.json"):
        is_valid, exc = validate_file(vuln_file)
        print_validity(is_valid, exc, vuln_file)


if __name__ == "__main__":
    try:
        is_valid, exc = validate_file(sys.argv[1])
        print_validity(is_valid, exc, sys.argv[1])
        exit(0)
    except IndexError:
        pass
    validate_all()
