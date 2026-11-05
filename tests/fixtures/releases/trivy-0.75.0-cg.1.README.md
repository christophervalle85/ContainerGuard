# Real patched Trivy CycloneDX fixture

`trivy-0.75.0-cg.1.cdx17.json` is raw, unmodified local tool output, not synthetic native provenance and not a release candidate.

Generated with existing local scanner image `sha256:842bcad166bcec33597bbf41615667cef0a902fb5a0b43fee5d1cba09896f423` (reported version `0.75.0+cg.1`) against the owned local amd64 image `cg-library-check-02a81f` exported to a Docker archive. Scanner command: `image --input /input/image.tar --scanners license --format cyclonedx --skip-db-update --skip-java-db-update --offline-scan --config '' --ignorefile ''`. Container used `--network=none`, a read-only owned archive mount and disposable `/tmp`; no Docker socket, private configuration or host home mounted.

123,863 bytes; SHA256 `845fe5e9b57e0dec14a52bcec7ff691fdcdc3022fa67ac178cff63d930e7b2ee`; CycloneDX 1.7, 71 components. Complete pinned offline schema validation and real Gitleaks 8.30.1 + unchanged metadata privacy audit passed before retaining it. This qualifies real producer output/validation, not the host `generate()` orchestration or a signed release.
