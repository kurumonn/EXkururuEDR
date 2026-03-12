from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TrustedSource:
    source_id: str
    secret: str
    enabled: bool = True


class TrustedSourceRegistry:
    def __init__(self, sources: dict[str, TrustedSource]) -> None:
        self._sources = sources

    @classmethod
    def from_json_file(cls, path: str) -> "TrustedSourceRegistry":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        raw_sources = payload.get("sources", [])
        sources: dict[str, TrustedSource] = {}
        for item in raw_sources:
            source = TrustedSource(
                source_id=str(item.get("source_id", "")),
                secret=str(item.get("secret", "")),
                enabled=bool(item.get("enabled", True)),
            )
            if source.source_id:
                sources[source.source_id] = source
        return cls(sources)

    def get(self, source_id: str) -> TrustedSource | None:
        source = self._sources.get(source_id)
        if not source or not source.enabled:
            return None
        return source

