import hashlib
import math
from collections import Counter
from datetime import datetime, timezone

import pefile
from sqlalchemy.orm import Session

# Optional: phone (Termux) installs may lack a cryptography build. Without it a signed PE is
# still reported as signed; only the signer's name can't be extracted.
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7
except ImportError:
    x509 = pkcs7 = None

import models

# APIs commonly seen together in process-injection / dynamic-loading malware patterns.
# Presence alone isn't proof of malice (plenty of legitimate software uses these too) —
# it's one heuristic signal among several, disclosed to the user as such.
SUSPICIOUS_IMPORT_GROUPS = [
    ({"VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, "process-injection API combination"),
    ({"LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualProtect"}, "dynamic code-loading + memory-permission change combination"),
    ({"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "WinExec"}, "download-and-execute API combination"),
    ({"IsDebuggerPresent", "CheckRemoteDebuggerPresent"}, "anti-debugging checks"),
]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _pe_string(entry) -> str | None:
    if entry is None:
        return None
    try:
        return entry.decode("utf-8", errors="ignore").strip() or None
    except AttributeError:
        return None


def _extract_pe_metadata(pe: pefile.PE) -> dict:
    out = {
        "company_name": None, "copyright": None, "product_name": None,
        "original_filename": None, "file_description": None, "file_version": None,
    }
    if not hasattr(pe, "FileInfo"):
        return out
    for file_info_list in pe.FileInfo:
        for entry in file_info_list:
            if entry.Key.decode(errors="ignore") != "StringFileInfo":
                continue
            for st in entry.StringTable:
                for k, v in st.entries.items():
                    key = _pe_string(k)
                    val = _pe_string(v)
                    if key == "CompanyName":
                        out["company_name"] = val
                    elif key == "LegalCopyright":
                        out["copyright"] = val
                    elif key == "ProductName":
                        out["product_name"] = val
                    elif key == "OriginalFilename":
                        out["original_filename"] = val
                    elif key == "FileDescription":
                        out["file_description"] = val
                    elif key == "FileVersion":
                        out["file_version"] = val
    return out


def _extract_signature(data: bytes, pe: pefile.PE) -> tuple[bool, str | None]:
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    except (AttributeError, IndexError, KeyError):
        return False, None
    if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
        return False, None
    # WIN_CERTIFICATE: 8-byte header (length, revision, cert type) then a DER PKCS#7 SignedData blob.
    cert_blob = data[sec_dir.VirtualAddress + 8: sec_dir.VirtualAddress + sec_dir.Size]
    if pkcs7 is None:
        return True, None
    try:
        certs = pkcs7.load_der_pkcs7_certificates(cert_blob)
    except Exception:
        return True, None
    if not certs:
        return True, None
    leaf = certs[0]
    try:
        cn = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        signer = cn[0].value if cn else leaf.subject.rfc4514_string()
    except Exception:
        signer = None
    return True, signer


def _suspicious_imports(pe: pefile.PE) -> list[str]:
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return []
    imported = set()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            name = _pe_string(imp.name)
            if name:
                imported.add(name)
    hits = []
    for group, label in SUSPICIOUS_IMPORT_GROUPS:
        if group.issubset(imported):
            hits.append(label)
    return hits


def analyze_file(db: Session, data: bytes, filename: str | None) -> models.FileLookup:
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    existing = db.query(models.FileLookup).filter(models.FileLookup.sha256 == sha256).first()
    now = datetime.now(timezone.utc)
    if existing:
        existing.last_seen_at = now
        existing.submission_count = (existing.submission_count or 1) + 1
        if filename and not existing.filename:
            existing.filename = filename
        db.commit()
        db.refresh(existing)
        return existing

    entropy = _shannon_entropy(data)
    is_pe = data[:2] == b"MZ"

    risk_score = 0.0
    risk_factors: list[str] = []
    security_checks: list[dict] = []
    meta = {"company_name": None, "copyright": None, "product_name": None,
            "original_filename": None, "file_description": None, "file_version": None}
    is_signed = False
    signer_name = None

    if is_pe:
        try:
            pe = pefile.PE(data=data, fast_load=False)
            meta = _extract_pe_metadata(pe)
            is_signed, signer_name = _extract_signature(data, pe)
            suspicious = _suspicious_imports(pe)
            if suspicious:
                risk_score += 20 * len(suspicious)
                for label in suspicious:
                    risk_factors.append(f"Imports match a {label}")
                security_checks.append({
                    "name": "Suspicious API Imports", "flagged": True,
                    "detail": "Matches: " + "; ".join(suspicious),
                })
            else:
                security_checks.append({
                    "name": "Suspicious API Imports", "flagged": False,
                    "detail": "No suspicious import combinations found",
                })

            if is_signed:
                security_checks.append({
                    "name": "Digital Signature", "flagged": False,
                    "detail": f"Signed by {signer_name}" if signer_name else "Authenticode signature present",
                })
            else:
                risk_score += 20
                risk_factors.append("No Authenticode digital signature present")
                security_checks.append({
                    "name": "Digital Signature", "flagged": True,
                    "detail": "No Authenticode signature present",
                })

            if meta["original_filename"] and filename:
                if meta["original_filename"].lower() != filename.lower():
                    risk_score += 10
                    risk_factors.append(
                        f"Embedded original filename ('{meta['original_filename']}') differs from the submitted filename"
                    )
                    security_checks.append({
                        "name": "Filename Consistency", "flagged": True,
                        "detail": f"Embedded name '{meta['original_filename']}' differs from submitted name '{filename}'",
                    })
                else:
                    security_checks.append({
                        "name": "Filename Consistency", "flagged": False,
                        "detail": "Embedded filename matches submitted filename",
                    })
        except pefile.PEFormatError:
            is_pe = False
            risk_score += 10
            risk_factors.append("File has an MZ header but is not a well-formed PE image")
            security_checks.append({
                "name": "PE Structure", "flagged": True,
                "detail": "MZ header present but not a well-formed PE image",
            })
    else:
        risk_factors.append("Not a PE (.exe/.dll) file — signature/copyright metadata unavailable")
        security_checks.append({
            "name": "PE Structure", "flagged": False,
            "detail": "Not a PE (.exe/.dll) file",
        })

    if entropy > 7.2:
        risk_score += 30
        risk_factors.append(f"High file entropy ({entropy:.2f}/8.0) — consistent with packing or encryption")
        security_checks.append({
            "name": "File Entropy", "flagged": True,
            "detail": f"{entropy:.2f}/8.0 — consistent with packing or encryption",
        })
    elif entropy > 6.8:
        risk_score += 10
        risk_factors.append(f"Elevated file entropy ({entropy:.2f}/8.0)")
        security_checks.append({
            "name": "File Entropy", "flagged": True,
            "detail": f"{entropy:.2f}/8.0 — elevated",
        })
    else:
        security_checks.append({
            "name": "File Entropy", "flagged": False,
            "detail": f"{entropy:.2f}/8.0 — normal range",
        })

    risk_score = min(risk_score, 100.0)

    row = models.FileLookup(
        sha256=sha256, sha1=sha1, md5=md5, filename=filename, size_bytes=len(data),
        is_pe=is_pe, pe_company_name=meta["company_name"], pe_copyright=meta["copyright"],
        pe_product_name=meta["product_name"], pe_original_filename=meta["original_filename"],
        pe_file_description=meta["file_description"], pe_file_version=meta["file_version"],
        is_signed=is_signed, signer_name=signer_name, entropy=round(entropy, 3),
        risk_score=round(risk_score, 1), risk_factors=risk_factors, security_checks=security_checks,
        first_seen_at=now, last_seen_at=now, submission_count=1,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def lookup_hash(db: Session, sha256: str) -> models.FileLookup | None:
    return db.query(models.FileLookup).filter(models.FileLookup.sha256 == sha256.lower()).first()
