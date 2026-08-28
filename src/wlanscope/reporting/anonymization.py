from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE = re.compile(r"(?i)(?<![0-9a-f:])[0-9a-f:]*:[0-9a-f:]+(?![0-9a-f:])")
_MAC = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
_GUID = re.compile(
    r"(?i)(?<![0-9a-f])\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\}?(?![0-9a-f])"
)
_LOCAL_PATH = re.compile(
    r"(?i)(?:[\"'](?:[a-z]:\\|\\\\)[^\r\n\"']+[\"']|(?:[a-z]:\\|\\\\)[^\s\"']+)"
)


class ReportAnonymizer:
    def __init__(self) -> None:
        self._mappings: dict[str, dict[str, str]] = {}

    def ipv4(self, value: IPv4Address | IPv4Network | str) -> str:
        return self._alias("IPV4", str(value))

    def ipv6(self, value: IPv6Address | IPv6Network | str) -> str:
        return self._alias("IPV6", str(value))

    def ip(
        self,
        value: IPv4Address | IPv4Network | IPv6Address | IPv6Network,
    ) -> str:
        return self.ipv4(value) if value.version == 4 else self.ipv6(value)

    def mac(self, value: str) -> str:
        return self._alias("MAC", value)

    def bssid(self, value: str) -> str:
        return self._alias("BSSID", value)

    def ssid(self, value: str) -> str:
        return self._alias("WIFI", value)

    def hostname(self, value: str) -> str:
        return self._alias("HOST", value)

    def profile(self, value: str) -> str:
        return self._alias("PROFILE", value)

    def interface(self, value: str) -> str:
        return self._alias("INTERFACE", value)

    def identifier(self, value: str) -> str:
        return self._alias("ID", value)

    def domain(self, value: str) -> str:
        return self._alias("DOMAIN", value)

    def sanitize_text(self, value: str) -> str:
        sanitized = value
        known_values = (
            (original, alias)
            for mapping in self._mappings.values()
            for original, alias in mapping.items()
        )
        for original, alias in sorted(known_values, key=lambda item: len(item[0]), reverse=True):
            sanitized = re.sub(re.escape(original), alias, sanitized, flags=re.IGNORECASE)
        sanitized = _LOCAL_PATH.sub(lambda match: self._alias("PATH", match.group()), sanitized)
        sanitized = _GUID.sub(lambda match: self.identifier(match.group()), sanitized)
        sanitized = _MAC.sub(lambda match: self.mac(match.group()), sanitized)
        sanitized = _IPV4.sub(lambda match: self.ipv4(match.group()), sanitized)
        return _IPV6_CANDIDATE.sub(self._sanitize_ipv6_candidate, sanitized)

    def finalize_aliases(self) -> None:
        originals = {
            original.casefold() for mapping in self._mappings.values() for original in mapping
        }
        used: set[str] = set()
        for category, mapping in self._mappings.items():
            index = 1
            for original in mapping:
                alias = f"{category}-{index:03d}"
                while alias.casefold() in originals or alias.casefold() in used:
                    index += 1
                    alias = f"{category}-{index:03d}"
                mapping[original] = alias
                used.add(alias.casefold())
                index += 1

    def _sanitize_ipv6_candidate(self, match: re.Match[str]) -> str:
        candidate = match.group()
        try:
            IPv6Address(candidate)
        except ValueError:
            return candidate
        return self.ipv6(candidate)

    def _alias(self, category: str, value: str) -> str:
        mapping = self._mappings.setdefault(category, {})
        alias = mapping.get(value)
        if alias is None:
            reserved = {
                item.casefold()
                for existing in self._mappings.values()
                for item in (*existing.keys(), *existing.values())
            }
            reserved.add(value.casefold())
            index = 1
            alias = f"{category}-{index:03d}"
            while alias.casefold() in reserved:
                index += 1
                alias = f"{category}-{index:03d}"
            mapping[value] = alias
        return alias
