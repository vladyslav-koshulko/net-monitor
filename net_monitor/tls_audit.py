from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509

TLS_VERSIONS = {(3, 0): "SSLv3", (3, 1): "TLS1.0", (3, 2): "TLS1.1", (3, 3): "TLS1.2", (3, 4): "TLS1.3"}

SIG_ALG_NAMES = {
    0x0101: "rsa_pkcs1_md5",
    0x0201: "rsa_pkcs1_sha1",
    0x0202: "dsa_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
}

WEAK_SIG_ALGS = {0x0101, 0x0201, 0x0202, 0x0203}

WEAK_CIPHERS = {
    0x0004,  # TLS_RSA_WITH_RC4_128_MD5
    0x0005,  # TLS_RSA_WITH_RC4_128_SHA
    0x000A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
}

CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}


def _iter_tls_records(data: bytes):
    i = 0
    n = len(data)
    while i + 5 <= n:
        content_type = data[i]
        major = data[i + 1]
        minor = data[i + 2]
        rec_len = int.from_bytes(data[i + 3 : i + 5], "big")
        if content_type not in (20, 21, 22, 23) or major != 3 or rec_len <= 0:
            i += 1
            continue
        end = i + 5 + rec_len
        if end > n:
            break
        yield content_type, (major, minor), data[i + 5 : end]
        i = end


def _iter_handshakes(payload: bytes):
    i = 0
    n = len(payload)
    while i + 4 <= n:
        htype = payload[i]
        hlen = int.from_bytes(payload[i + 1 : i + 4], "big")
        end = i + 4 + hlen
        if end > n:
            break
        yield htype, payload[i + 4 : end]
        i = end


def _extract_client_hello_info(body: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if len(body) < 42:
        return out

    version = (body[0], body[1])
    out["client_version"] = TLS_VERSIONS.get(version, f"{version[0]}.{version[1]}")

    p = 34
    if p >= len(body):
        return out
    sid_len = body[p]
    p += 1 + sid_len
    if p + 2 > len(body):
        return out

    cs_len = int.from_bytes(body[p : p + 2], "big")
    p += 2
    if p + cs_len > len(body):
        return out

    ciphers = [int.from_bytes(body[i : i + 2], "big") for i in range(p, p + cs_len, 2) if i + 2 <= p + cs_len]
    p += cs_len
    out["offered_cipher_suites"] = [f"0x{x:04x}" for x in ciphers[:50]]

    if p >= len(body):
        return out
    comp_len = body[p]
    p += 1 + comp_len
    if p + 2 > len(body):
        return out

    ext_total = int.from_bytes(body[p : p + 2], "big")
    p += 2
    if p + ext_total > len(body):
        return out

    ext_end = p + ext_total
    ext_ids: List[int] = []
    curves: List[int] = []
    ec_pf: List[int] = []
    sig_algs: List[int] = []

    while p + 4 <= ext_end:
        etype = int.from_bytes(body[p : p + 2], "big")
        elen = int.from_bytes(body[p + 2 : p + 4], "big")
        p += 4
        if p + elen > ext_end:
            break
        edata = body[p : p + elen]
        p += elen

        ext_ids.append(etype)

        if etype == 0 and elen >= 5:
            list_len = int.from_bytes(edata[0:2], "big")
            if list_len + 2 <= len(edata) and len(edata) >= 5:
                host_len = int.from_bytes(edata[3:5], "big")
                host_end = 5 + host_len
                if host_end <= len(edata):
                    host = edata[5:host_end].decode("utf-8", errors="ignore")
                    if host:
                        out["sni"] = host

        if etype == 10 and elen >= 4:
            glen = int.from_bytes(edata[0:2], "big")
            for j in range(2, min(2 + glen, len(edata)), 2):
                if j + 2 <= len(edata):
                    curves.append(int.from_bytes(edata[j : j + 2], "big"))

        if etype == 11 and elen >= 2:
            flen = edata[0]
            ec_pf.extend(list(edata[1 : 1 + flen]))

        if etype == 13 and elen >= 2:
            slen = int.from_bytes(edata[0:2], "big")
            for j in range(2, min(2 + slen, len(edata)), 2):
                if j + 2 <= len(edata):
                    sig_algs.append(int.from_bytes(edata[j : j + 2], "big"))

    ja3_str = (
        f"{version[0] * 256 + version[1]},"
        f"{'-'.join(str(x) for x in ciphers)},"
        f"{'-'.join(str(x) for x in ext_ids)},"
        f"{'-'.join(str(x) for x in curves)},"
        f"{'-'.join(str(x) for x in ec_pf)}"
    )
    ja3 = "".join(ja3_str)
    out["ja3"] = hashlib.md5(ja3.encode("utf-8")).hexdigest()
    out["ja3_string"] = ja3
    out["ja4_like"] = hashlib.sha1(body[:120]).hexdigest()[:24]

    if sig_algs:
        names = [SIG_ALG_NAMES.get(x, f"0x{x:04x}") for x in sig_algs]
        weak = [SIG_ALG_NAMES.get(x, f"0x{x:04x}") for x in sig_algs if x in WEAK_SIG_ALGS]
        out["signature_algorithms"] = names
        out["weak_signature_algorithms"] = weak

    return out


def _extract_server_hello_info(body: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if len(body) < 38:
        return out

    version = (body[0], body[1])
    out["server_version"] = TLS_VERSIONS.get(version, f"{version[0]}.{version[1]}")

    p = 34
    sid_len = body[p]
    p += 1 + sid_len
    if p + 2 > len(body):
        return out
    cipher = int.from_bytes(body[p : p + 2], "big")
    out["cipher_suite_id"] = f"0x{cipher:04x}"
    out["cipher_suite_name"] = CIPHER_NAMES.get(cipher, f"UNKNOWN_0x{cipher:04x}")

    if cipher in WEAK_CIPHERS or "CBC" in out["cipher_suite_name"]:
        out["cipher_quality"] = "weak"
    elif "GCM" in out["cipher_suite_name"] or "CHACHA20" in out["cipher_suite_name"]:
        out["cipher_quality"] = "strong"
    else:
        out["cipher_quality"] = "unknown"

    return out


def _extract_certs_from_handshake(body: bytes) -> List[bytes]:
    certs: List[bytes] = []
    if len(body) < 4:
        return certs

    start = 0
    if len(body) >= 4:
        context_len = body[0]
        if 1 + context_len + 3 <= len(body):
            start = 1 + context_len

    if start + 3 > len(body):
        return certs

    total_len = int.from_bytes(body[start : start + 3], "big")
    p = start + 3
    end = min(p + total_len, len(body))

    while p + 3 <= end:
        clen = int.from_bytes(body[p : p + 3], "big")
        p += 3
        if p + clen > end:
            break
        cert_der = body[p : p + clen]
        p += clen
        certs.append(cert_der)
        if p + 2 <= end:
            ext_len = int.from_bytes(body[p : p + 2], "big")
            if p + 2 + ext_len <= end:
                p += 2 + ext_len

    return certs


def _cert_summary(der_bytes: bytes) -> Optional[Dict[str, Any]]:
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        return None

    now = datetime.now(timezone.utc)
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    days = int((not_after - now).total_seconds() // 86400)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_after": not_after.isoformat(),
        "days_to_expiry": days,
        "expired": days < 0,
    }


def parse_tls_metadata(stream_bytes: bytes) -> Dict[str, Any]:
    tls: Dict[str, Any] = {}
    certs: List[Dict[str, Any]] = []

    for content_type, version, record_payload in _iter_tls_records(stream_bytes):
        if "record_version" not in tls:
            tls["record_version"] = TLS_VERSIONS.get(version, f"{version[0]}.{version[1]}")

        if content_type != 22:
            continue

        for htype, hbody in _iter_handshakes(record_payload):
            if htype == 1:
                tls.update(_extract_client_hello_info(hbody))
            elif htype == 2:
                tls.update(_extract_server_hello_info(hbody))
            elif htype == 11:
                for der in _extract_certs_from_handshake(hbody):
                    cs = _cert_summary(der)
                    if cs:
                        certs.append(cs)

    if certs:
        tls["certificate_chain"] = certs
        leaf = certs[0]
        tls["leaf_subject"] = leaf.get("subject")
        tls["leaf_issuer"] = leaf.get("issuer")
        tls["leaf_days_to_expiry"] = leaf.get("days_to_expiry")
        tls["leaf_expired"] = leaf.get("expired")

    return tls
