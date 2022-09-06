from typing import Dict, Optional, List


def extract_cve_id(cve_entry: Dict):
    return cve_entry["cve"]["CVE_data_meta"]["ID"]


def _convert_reference(reference: Dict[str, str]) -> Dict:
    ref_type = "WEB"

    if "github.com/advisories/" in reference["url"]:
        ref_type = "ADVISORY"

    if "nvd.nist.gov/vuln/detail/" in reference["url"]:
        ref_type = "ADVISORY"

    if "cve.mitre.org/cgi-bin/cvename.cgi" in reference["url"]:
        ref_type = "ADVISORY"

    # Find potential patch entries
    if "trac.wordpress.org" in reference["url"]:
        for tag in reference.get("tags", []):
            if tag == "Patch":
                ref_type = "FIX"
                break

    return {
        "type": ref_type,
        "url": reference["url"],
    }


def extract_references(cve_entry: Dict) -> List[Dict]:
    references = []
    has_advisory = False
    for ref_data in cve_entry["cve"]["references"]["reference_data"]:
        converted_ref = _convert_reference(ref_data)
        if converted_ref.get("type") == "ADIVSORY":
            has_advisory = True
        references.append(converted_ref)

    if has_advisory is False:
        cve_id = extract_cve_id(cve_entry)
        references.append({
            "type": "ADVISORY",
            "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
        })
    return references


def extract_details(cve_entry: Dict) -> Optional[str]:
    for description_data in cve_entry["cve"]["description"]["description_data"]:
        if description_data.get("lang", "") == "en":
            raw_description = description_data.get("value", "").strip()
            if len(raw_description) == 0:
                return None
            return raw_description


def extract_severity(cve_entry: Dict) -> Optional[List[Dict]]:
    try:
        vector_string = cve_entry["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
    except (KeyError, TypeError):
        return None
    return [{
        "score": vector_string,
        "type": "CVSS_V3"
    }]


def extract_modified(cve_entry: Dict) -> Optional[str]:
    return cve_entry["publishedDate"]


def extract_published(cve_entry: Dict) -> Optional[str]:
    return cve_entry["lastModifiedDate"]


def extract_cwe_ids(cve_entry: Dict) -> List[Dict]:
    cwe_ids = []
    for problemtype_data in cve_entry["cve"]["problemtype"]["problemtype_data"]:
        for description in problemtype_data["description"]:
            if description["lang"] == "en" and description["value"].startswith("CWE-"):
                cwe_ids.append(description["value"])
    return cwe_ids

def extract_aliases(cve_entry: Dict) -> List[str]:
    return [extract_cve_id(cve_entry)]
