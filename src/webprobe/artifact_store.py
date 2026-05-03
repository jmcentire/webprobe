"""Canonical shared Artifact store (CA003).

The capture phase produces a single ArtifactStore per run. Dimension analyzers
read from this store; nobody copies. CheckResult.evidence references artifacts
by id, not by full payload.

Capture failures are stored as Artifacts with capture_status != ok and
capture_error populated, so dependent checks can return NOT_DETECTED with
reason="artifact_unavailable:..." (CA004) without re-fetching.

Persistence: in-memory during a run; ``persist(run_dir)`` writes JSON files
under ``runs/<run_id>/artifacts/``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable

from webprobe.models import Artifact, ArtifactType, CaptureStatus

logger = logging.getLogger(__name__)


class ArtifactStore:
    """In-memory canonical store. One per run.

    Indexed by artifact_id (primary), and by (artifact_type, source_url) for
    duplicate suppression and lookup. Putting an Artifact whose
    (artifact_type, source_url) already exists raises a DuplicateArtifactError
    by default; callers can pass ``replace=True`` to overwrite (e.g. when an
    initial capture failed and a retry succeeded).
    """

    def __init__(self) -> None:
        self._by_id: dict[str, Artifact] = {}
        self._by_key: dict[tuple[ArtifactType, str], str] = {}  # (type, url) -> artifact_id

    # ---- Mutation ----

    def put(self, artifact: Artifact, *, replace: bool = False) -> str:
        """Insert an artifact. Returns the artifact_id.

        Raises DuplicateArtifactError if an artifact with the same
        (artifact_type, source_url) already exists and replace=False.
        """
        key = (artifact.artifact_type, artifact.source_url)
        existing_id = self._by_key.get(key)
        if existing_id is not None and not replace:
            raise DuplicateArtifactError(
                f"Artifact already exists for ({artifact.artifact_type.value}, {artifact.source_url}); "
                "pass replace=True to overwrite"
            )
        if existing_id is not None and replace:
            # Drop the previous id mapping
            self._by_id.pop(existing_id, None)
        self._by_id[artifact.artifact_id] = artifact
        self._by_key[key] = artifact.artifact_id
        return artifact.artifact_id

    def record_failure(
        self,
        artifact_type: ArtifactType,
        source_url: str,
        capture_status: CaptureStatus,
        capture_error: str,
        *,
        elapsed_ms: float = 0.0,
        replace: bool = False,
    ) -> str:
        """Convenience: record a capture failure as an Artifact (CA004).

        Dependent checks consume the resulting Artifact and emit NOT_DETECTED
        with reason="artifact_unavailable:<artifact_type>:<reason>".
        """
        if capture_status == CaptureStatus.ok:
            raise ValueError("record_failure called with capture_status=ok")
        artifact = Artifact(
            artifact_type=artifact_type,
            source_url=source_url,
            capture_status=capture_status,
            capture_error=capture_error,
            elapsed_ms=elapsed_ms,
        )
        return self.put(artifact, replace=replace)

    # ---- Read ----

    def get(self, artifact_id: str) -> Artifact | None:
        """Fetch by artifact_id; returns None if absent."""
        return self._by_id.get(artifact_id)

    def find(
        self,
        artifact_type: ArtifactType,
        source_url: str,
    ) -> Artifact | None:
        """Fetch by (type, url); returns None if absent.

        This is the primary lookup checks should use — it returns whatever the
        capture phase recorded for that artifact, including failure markers.
        """
        aid = self._by_key.get((artifact_type, source_url))
        if aid is None:
            return None
        return self._by_id.get(aid)

    def find_by_type(self, artifact_type: ArtifactType) -> list[Artifact]:
        """All artifacts of a given type, regardless of URL."""
        return [a for a in self._by_id.values() if a.artifact_type == artifact_type]

    def find_by_url(
        self, source_url: str, artifact_type: ArtifactType | None = None
    ) -> list[Artifact]:
        """All artifacts for a URL, optionally filtered by type."""
        result = []
        for a in self._by_id.values():
            if a.source_url != source_url:
                continue
            if artifact_type is not None and a.artifact_type != artifact_type:
                continue
            result.append(a)
        return result

    def all(self) -> Iterable[Artifact]:
        """Iterate all artifacts. Order is insertion order (Python 3.7+ dict)."""
        return self._by_id.values()

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, artifact_id: str) -> bool:
        return artifact_id in self._by_id

    # ---- Persistence ----

    def persist(self, run_dir: Path | str) -> Path:
        """Write artifacts to ``<run_dir>/artifacts/``.

        Each artifact is serialized as JSON. ``raw_bytes`` is base64-encoded if
        present. Returns the artifacts directory path.
        """
        run_dir = Path(run_dir)
        artifacts_dir = run_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        for artifact in self._by_id.values():
            data = artifact.model_dump(mode="json")
            if artifact.raw_bytes is not None:
                import base64

                data["raw_bytes_b64"] = base64.b64encode(artifact.raw_bytes).decode("ascii")
                data["raw_bytes"] = None
            out = artifacts_dir / f"{artifact.artifact_id}.json"
            out.write_text(json.dumps(data, indent=2, sort_keys=True))
        logger.info(
            "artifact_store.persisted",
            extra={"count": len(self._by_id), "run_dir": str(run_dir)},
        )
        return artifacts_dir

    @classmethod
    def load(cls, run_dir: Path | str) -> ArtifactStore:
        """Reconstitute a store from ``<run_dir>/artifacts/`` (replay/diff use)."""
        run_dir = Path(run_dir)
        artifacts_dir = run_dir / "artifacts"
        store = cls()
        if not artifacts_dir.exists():
            return store
        for path in sorted(artifacts_dir.glob("*.json")):
            data = json.loads(path.read_text())
            raw_b64 = data.pop("raw_bytes_b64", None)
            data["raw_bytes"] = None
            artifact = Artifact.model_validate(data)
            if raw_b64 is not None:
                import base64

                artifact.raw_bytes = base64.b64decode(raw_b64)
            # Insert with replace=True so reload is idempotent
            store.put(artifact, replace=True)
        return store


class DuplicateArtifactError(ValueError):
    """Raised by put() when an artifact already exists for (type, url) and replace=False."""
