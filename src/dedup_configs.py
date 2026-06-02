#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
from collections import Counter, OrderedDict
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("dedup_configs")

# -----------------------------------------------------------------------------
# Canonicalization policy
# -----------------------------------------------------------------------------
IGNORED_REMARK_KEYS = {"ps", "remark", "alias", "name", "tag"}

# Values that are usually case-insensitive in share links.
LOWER_VALUE_KEYS = {
    "type",
    "security",
    "fp",
    "alpn",
    "sni",
    "flow",
    "encryption",
    "headertype",
    "network",
    "net",
    "tls",
    "scy",
    "mode",
    "proto",
}

# Known host-like values that should be lowercased.
HOST_VALUE_KEYS = {
    "add",
    "host",
    "sni",
    "server",
    "servername",
    "address",
}

# Known UUID / identifier fields that are case-insensitive.
UUID_VALUE_KEYS = {
    "id",
    "uuid",
}

# Number-ish fields that are typically represented as strings in share links.
STRING_NUMBER_KEYS = {
    "port",
    "aid",
    "alterid",
    "mtu",
    "tti",
    "udpport",
    "tcpport",
    "packetencoding",
}

SCHEME_ALIASES = {
    "shadowsocks": "ss",
    "socks5": "socks",
    "hy2": "hysteria2",
}

BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def safe_b64_decode_text(text: str) -> Optional[bytes]:
    """
    Decode standard or URL-safe base64, with or without padding.
    Returns None on failure.
    """
    s = re.sub(r"\s+", "", text or "")
    if not s:
        return None

    candidates = (s, s + "=" * (-len(s) % 4))
    for candidate in candidates:
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                return decoder(candidate.encode("utf-8"))
            except Exception:
                continue
    return None


def b64_encode_nopad(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8").rstrip("=")


def is_probably_base64_line(text: str) -> bool:
    s = re.sub(r"\s+", "", text or "")
    if len(s) < 16:
        return False
    if "://" in s or "@" in s or "#" in s or "?" in s:
        return False
    return bool(BASE64_RE.fullmatch(s))


def decode_subscription_payload_if_needed(text: str) -> str:
    """
    If the whole file is a base64-encoded subscription body, decode it.
    Otherwise return the original text.
    """
    raw = text.strip()
    if not raw:
        return text

    # If it already contains direct URIs, leave it alone.
    if "://" in raw:
        return text

    decoded = safe_b64_decode_text(raw)
    if not decoded:
        return text

    decoded_text = decoded.decode("utf-8", errors="ignore")
    if "://" in decoded_text:
        return decoded_text
    return text


def parse_host_port(host_port: str) -> tuple[str, Optional[int]]:
    """
    Parse host[:port], with IPv6 brackets supported.
    Returns (host, port_or_None).
    """
    s = (host_port or "").strip()
    if not s:
        return "", None

    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            return s.lower(), None
        host = s[1:end].lower()
        rest = s[end + 1 :]
        if rest.startswith(":"):
            port_str = rest[1:].strip()
            if port_str.isdigit():
                return host, int(port_str)
        return host, None

    if s.count(":") == 1:
        host, port_str = s.rsplit(":", 1)
        host = host.lower().strip()
        if port_str.isdigit():
            return host, int(port_str)
        return host, None

    # Multiple colons usually means a raw IPv6 literal without brackets.
    return s.lower(), None


def normalize_scalar(key: str, value: Any, *, lower_sensitive: bool = False) -> Any:
    """
    Normalize a scalar value for dedup key generation.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        if key in STRING_NUMBER_KEYS:
            return str(int(value))
        return value

    if isinstance(value, str):
        s = value.strip()
        if key in UUID_VALUE_KEYS or lower_sensitive:
            return s.lower()
        if key in HOST_VALUE_KEYS:
            return s.lower()
        if key in LOWER_VALUE_KEYS:
            return s.lower()
        if key in STRING_NUMBER_KEYS and s.isdigit():
            return str(int(s))
        return s

    if isinstance(value, list):
        return [normalize_scalar(key, item, lower_sensitive=lower_sensitive) for item in value]

    if isinstance(value, dict):
        items = []
        for k, v in value.items():
            lk = str(k).strip().lower()
            if lk in IGNORED_REMARK_KEYS:
                continue
            items.append((lk, normalize_scalar(lk, v)))
        items.sort(
            key=lambda x: (
                x[0],
                json.dumps(x[1], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            )
        )
        return {k: v for k, v in items}

    return str(value).strip()


def canonical_query_pairs(query: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for key, value in parse_qsl(query, keep_blank_values=True, strict_parsing=False):
        lk = key.strip().lower()
        if lk in IGNORED_REMARK_KEYS:
            continue
        nv = normalize_scalar(lk, value)
        if isinstance(nv, str):
            pairs.append((lk, nv))
        else:
            pairs.append((lk, json.dumps(nv, ensure_ascii=False, sort_keys=True, separators=(",", ":"))))
    pairs.sort(key=lambda x: (x[0], x[1]))
    return pairs


def build_uri(
    scheme: str,
    userinfo: Optional[str],
    host: str,
    port: Optional[int],
    path: str = "",
    query_pairs: Optional[list[tuple[str, str]]] = None,
    fragment: str = "",
) -> str:
    """
    Build a normalized URI.
    """
    netloc = ""

    if userinfo:
        netloc += quote(userinfo, safe="")
        netloc += "@"

    if host:
        if ":" in host and not host.startswith("["):
            netloc += f"[{host}]"
        else:
            netloc += host.lower()

    if port is not None:
        netloc += f":{int(port)}"

    query = urlencode(query_pairs or [], doseq=True) if query_pairs else ""
    return urlunsplit((scheme, netloc, path or "", query, fragment or ""))


# -----------------------------------------------------------------------------
# Protocol-specific normalizers
# -----------------------------------------------------------------------------
def normalize_vmess(raw: str) -> tuple[Optional[str], Optional[str]]:
    """
    Returns: (dedup_key, canonical_uri)
    """
    if "://" not in raw:
        return None, None

    payload = raw.split("://", 1)[1].strip()
    decoded = safe_b64_decode_text(payload)
    if not decoded:
        return None, None

    try:
        obj = json.loads(decoded.decode("utf-8", errors="ignore"))
    except Exception:
        return None, None

    if not isinstance(obj, dict):
        return None, None

    normalized: dict[str, Any] = {}
    for k, v in obj.items():
        lk = str(k).strip().lower()
        if lk in IGNORED_REMARK_KEYS:
            continue
        normalized[lk] = normalize_scalar(lk, v, lower_sensitive=(lk == "id"))

    key_json = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    # Keep share-link style JSON values as strings where that is typical.
    rewrite_obj: dict[str, Any] = {}
    for k, v in normalized.items():
        if k in STRING_NUMBER_KEYS and v is not None:
            rewrite_obj[k] = str(v)
        else:
            rewrite_obj[k] = v

    rewrite_json = json.dumps(
        rewrite_obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    canonical_uri = f"vmess://{b64_encode_nopad(rewrite_json.encode('utf-8'))}"
    return key_json, canonical_uri


def normalize_ss(raw: str) -> tuple[Optional[str], Optional[str]]:
    """
    Normalize Shadowsocks / SIP002.
    """
    if "://" not in raw:
        return None, None

    _, rest = raw.split("://", 1)
    fragment = ""
    if "#" in rest:
        rest, fragment = rest.split("#", 1)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)

    host = ""
    port: Optional[int] = None
    method = ""
    password = ""
    query_pairs = canonical_query_pairs(query)

    # Case 1: SIP002 style ss://userinfo@host:port
    if "@" in rest:
        cred_part, host_port = rest.rsplit("@", 1)
        host, port = parse_host_port(host_port)

        decoded = safe_b64_decode_text(cred_part)
        if decoded:
            cred_text = decoded.decode("utf-8", errors="ignore")
            if ":" in cred_text:
                method, password = cred_text.split(":", 1)
                method = method.strip().lower()
                password = password.strip()
            else:
                method = cred_part.strip().lower()
        else:
            if ":" in cred_part:
                method, password = cred_part.split(":", 1)
                method = method.strip().lower()
                password = password.strip()
            else:
                method = cred_part.strip().lower()

    # Case 2: legacy ss://base64(method:password@host:port)
    else:
        decoded = safe_b64_decode_text(rest)
        if decoded:
            decoded_text = decoded.decode("utf-8", errors="ignore")
            if "@" in decoded_text and ":" in decoded_text:
                cred_part, host_port = decoded_text.rsplit("@", 1)
                host, port = parse_host_port(host_port)
                method, password = cred_part.split(":", 1)
                method = method.strip().lower()
                password = password.strip()

    if host:
        key_obj = {
            "scheme": "ss",
            "method": method,
            "password": password,
            "host": host.lower(),
            "port": port,
            "query": query_pairs,
        }
    else:
        key_obj = {
            "scheme": "ss",
            "raw": rest.strip(),
            "query": query_pairs,
        }

    key = json.dumps(key_obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    canonical_uri = None
    if host and port is not None and method:
        userinfo = b64_encode_nopad(f"{method}:{password}".encode("utf-8"))
        canonical_uri = build_uri("ss", userinfo, host.lower(), port, "", query_pairs, "")
    elif host:
        canonical_uri = build_uri("ss", None, host.lower(), port, "", query_pairs, "")

    return key, canonical_uri


def normalize_generic(raw: str, scheme_in: str) -> tuple[Optional[str], Optional[str]]:
    """
    Generic URI canonicalizer for VLESS / Trojan / SOCKS / Hysteria / TUIC / WireGuard / AnyTLS etc.
    """
    if "://" not in raw:
        return None, None

    parsed = urlsplit(raw)
    scheme = SCHEME_ALIASES.get(parsed.scheme.lower(), parsed.scheme.lower())
    if not scheme:
        return None, None

    # parsed.port can raise ValueError if the port is malformed, for example:
    # vless://user@host:…
    # In that case we should not crash the whole job.
    try:
        port = parsed.port
    except ValueError:
        logger.warning("Skipping invalid URI with bad port: %s", raw)
        return None, None

    userinfo = parsed.username or ""
    host = parsed.hostname or ""
    path = parsed.path or ""
    query_pairs = canonical_query_pairs(parsed.query)

    # VLESS UUID is case-insensitive. Trojan password is not.
    if scheme == "vless":
        userinfo = userinfo.lower()

    host = host.lower()

    key_obj = {
        "scheme": scheme,
        "userinfo": userinfo,
        "host": host,
        "port": port,
        "path": path,
        "query": query_pairs,
    }

    key = json.dumps(key_obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    canonical_uri = build_uri(scheme, userinfo or None, host, port, path, query_pairs, "")
    return key, canonical_uri


def normalize_config(raw: str) -> tuple[Optional[str], Optional[str]]:
    """
    Return (dedup_key, canonical_uri).
    """
    line = (raw or "").strip()
    if not line or line.startswith("#"):
        return None, None
    if "://" not in line:
        return None, None

    scheme = line.split("://", 1)[0].strip().lower()
    scheme = SCHEME_ALIASES.get(scheme, scheme)

    if scheme == "vmess":
        return normalize_vmess(line)
    if scheme == "ss":
        return normalize_ss(line)
    if scheme in {"vless", "trojan", "socks", "hysteria", "hysteria2", "tuic", "juicity", "wireguard", "anytls"}:
        return normalize_generic(line, scheme)

    # Unknown scheme: still do a safe generic dedup with host lowercasing and query sort.
    return normalize_generic(line, scheme)


# -----------------------------------------------------------------------------
# File handling
# -----------------------------------------------------------------------------
@dataclass
class StoredConfig:
    raw: str
    canonical: str


def load_candidate_lines(input_path: str) -> list[str]:
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    if "://" not in text:
        decoded = decode_subscription_payload_if_needed(text)
        if decoded != text:
            text = decoded

    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # If a single line itself is base64 subscription content, try to expand it.
        if "://" not in line and is_probably_base64_line(line):
            decoded = safe_b64_decode_text(line)
            if decoded:
                decoded_text = decoded.decode("utf-8", errors="ignore")
                if "://" in decoded_text:
                    for sub in decoded_text.splitlines():
                        sub = sub.strip()
                        if sub and not sub.startswith("#"):
                            lines.append(sub)
                    continue

        lines.append(line)

    return lines


def process_servers(input_path: str, output_path: str, *, rewrite: bool = False, sort_output: bool = False) -> None:
    logger.info("Processing %s", input_path)

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    lines = load_candidate_lines(input_path)

    unique: "OrderedDict[str, StoredConfig]" = OrderedDict()
    stats: Counter[str] = Counter()
    invalid = 0

    for raw_link in lines:
        if not raw_link or raw_link.startswith("#"):
            continue

        proto = raw_link.split("://", 1)[0].lower() if "://" in raw_link else "unknown"
        proto = SCHEME_ALIASES.get(proto, proto)

        canonical, normalized_uri = normalize_config(raw_link)
        if canonical is None:
            invalid += 1
            continue

        if canonical not in unique:
            unique[canonical] = StoredConfig(
                raw=raw_link,
                canonical=normalized_uri or raw_link,
            )
            stats[proto] += 1

    items = list(unique.items())
    if sort_output:
        items.sort(key=lambda kv: kv[0])

    with open(output_path, "w", encoding="utf-8") as f:
        for _, record in items:
            f.write((record.canonical if rewrite else record.raw).rstrip() + "\n")

    logger.info("Input: %d, Invalid: %d, Output: %d", len(lines), invalid, len(unique))
    for proto, count in stats.most_common():
        logger.info("%s: %d", proto, count)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deduplicate V2Ray/Xray share links using protocol-aware canonicalization."
    )
    parser.add_argument("input_file", help="Input file containing one config per line")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file. Default: overwrite input file via a temporary file.",
        default=None,
    )
    parser.add_argument(
        "--rewrite",
        action="store_true",
        help="Write normalized share links instead of the first raw occurrence.",
    )
    parser.add_argument(
        "--sort-output",
        action="store_true",
        help="Sort output by canonical key. Default keeps first-seen order.",
    )

    args = parser.parse_args()

    input_file = args.input_file
    output_file = args.output or f"{input_file}.tmp"

    process_servers(input_file, output_file, rewrite=args.rewrite, sort_output=args.sort_output)

    if args.output is None:
        os.replace(output_file, input_file)
        print(f"Dedup completed. Unique configs written to {input_file}")
    else:
        print(f"Dedup completed. Unique configs written to {output_file}")


if __name__ == "__main__":
    main()
