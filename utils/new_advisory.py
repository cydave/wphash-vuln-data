import hashlib

# TODO

def make_id(slug: str, cve_id: str) -> str:
    """Create a WPHSH identifier."""
    sh = hashlib.sha256(slug.encode()).hexdigest()[:12]
    ch = hashlib.sha256(cve_id.encode()).hexdigest()[:12]
    return f"WPHSH-{sh}-{ch}"
