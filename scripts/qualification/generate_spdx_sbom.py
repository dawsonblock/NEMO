#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Convert cargo-about's machine-readable license inventory to SPDX 2.3."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from typing import Any


def package_id(package: dict[str, Any]) -> str:
    digest = hashlib.sha256(package["id"].encode()).hexdigest()[:16]
    return f"SPDXRef-Package-{digest}"


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: generate_spdx_sbom.py <cargo-about.json> <spdx.json> <release-version>"
        )

    inventory = json.loads(pathlib.Path(sys.argv[1]).read_text())
    release_version = sys.argv[3]
    crates = inventory.get("crates", [])
    by_name = {crate["package"]["name"]: crate for crate in crates}
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []

    for crate in crates:
        package = crate["package"]
        spdx_id = package_id(package)
        source = package.get("source") or "NOASSERTION"
        license_expression = crate.get("license") or package.get("license") or "NOASSERTION"
        entry: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": package["name"],
            "versionInfo": package["version"],
            "downloadLocation": source,
            "licenseConcluded": license_expression,
            "licenseDeclared": package.get("license") or license_expression,
            "copyrightText": "NOASSERTION",
            "filesAnalyzed": False,
        }
        entry["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:cargo/{package['name']}@{package['version']}",
            }
        ]
        packages.append(entry)

        for dependency in package.get("dependencies", []):
            dependency_crate = by_name.get(dependency["name"])
            dependency_id = package_id(dependency_crate["package"]) if dependency_crate else None
            if dependency_id:
                relationships.append(
                    {
                        "spdxElementId": spdx_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": dependency_id,
                    }
                )

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"NEMO {release_version} Rust dependency inventory",
        "documentNamespace": f"https://github.com/dawsonblock/NEMO/spdx/{release_version}",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: cargo-about 0.9.1", "Organization: NVIDIA CORPORATION & AFFILIATES"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    pathlib.Path(sys.argv[2]).write_text(json.dumps(document, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
