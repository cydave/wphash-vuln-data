import glob
import json

import jsonschema


if __name__ == "__main__":
    with open("./schema.json") as fin:
        schema = json.load(fin)

    for vuln_file in glob.iglob("../advisories/*.json"):
        with open(vuln_file) as fin:
            raw_vuln = json.load(fin)
            try:
                jsonschema.validate(raw_vuln, schema=schema)
                print(f"[  VALID  ]: {vuln_file}")
            except jsonschema.ValidationError:
                print(f"[ INVALID ]: {vuln_file}")
