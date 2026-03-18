import json
from dataclasses import dataclass
from typing import Any

from packageurl import PackageURL

from hermeto.core.rooted_path import RootedPath


def _extract_artifact(
    artifact: dict[str, Any], result: dict[str, dict[str, str | None]]
) -> None:
    """Add an artifact's resolved URL and download info to result if not already present."""
    resolved_url = artifact.get("resolved")
    if resolved_url and resolved_url not in result:
        raw_checksum = artifact.get("checksum")
        result[resolved_url] = {
            # Some checksums have additional information after the hash (e.g. "abc123  filename.jar"),
            # so take only the first token.
            "checksum": raw_checksum.split()[0] if raw_checksum else None,
            "checksum_algorithm": artifact.get("checksumAlgorithm"),
            "group_id": artifact.get("groupId"),
            "artifact_id": artifact.get("artifactId"),
            "version": artifact.get("version"),
            "classifier": artifact.get("classifier"),
        }


def _extract_pom_chain(
    pom: dict[str, Any] | None, result: dict[str, dict[str, str | None]]
) -> None:
    """Recursively walk a pom and its parent chain, adding all POM URLs to result."""
    if not pom or not isinstance(pom, dict):
        return
    _extract_artifact(pom, result)
    _extract_pom_chain(pom.get("parent"), result)


def _extract_dependency(
    artifact: dict[str, Any], result: dict[str, dict[str, str | None]]
) -> None:
    """Collect an artifact, its full transitive subtree, pom parent chains, and bom imports."""
    _extract_artifact(artifact, result)
    _extract_pom_chain(artifact.get("parent"), result)
    _extract_pom_chain(artifact.get("pom"), result)
    for bom in artifact.get("boms", []):
        _extract_pom_chain(bom, result)
    for child in artifact.get("children", []):
        _extract_dependency(child, result)


def _components_from_dict(artifacts: dict[str, dict[str, Any]]) -> list["MavenComponent"]:
    """Build a deduplicated list of MavenComponent from an artifact download dict."""
    result = []
    for url, info in artifacts.items():
        group_id = info.get("group_id")
        artifact_id = info.get("artifact_id")
        version = info.get("version")
        if not (group_id and artifact_id and version):
            continue
        if url.endswith(".pom"):
            qualifiers = {"type": "pom"}
        else:
            qualifiers = {"type": "jar"}
            if classifier := info.get("classifier"):
                qualifiers["classifier"] = classifier
        purl = PackageURL(
            type="maven",
            namespace=group_id,
            name=artifact_id,
            version=version,
            qualifiers=qualifiers,
        )
        result.append(
            MavenComponent(
                name=f"{group_id}:{artifact_id}",
                purl=purl.to_string(),
                version=version,
                scope="",
            )
        )
    return result


@dataclass
class MavenComponent:
    """Maven component."""

    name: str
    purl: str
    version: str
    scope: str


class MavenDependency:
    """Maven dependency from lockfile.json."""

    def __init__(self, dependency_dict: dict[str, Any]) -> None:
        """Initialize a MavenDependency."""
        self._dependency_dict = dependency_dict

    @property
    def group_id(self) -> str:
        """Get the group ID."""
        return self._dependency_dict["groupId"]

    @property
    def artifact_id(self) -> str:
        """Get the artifact ID."""
        return self._dependency_dict["artifactId"]

    @property
    def version(self) -> str:
        """Get the version."""
        return self._dependency_dict["version"]

    @property
    def name(self) -> str:
        """Get the full name (groupId:artifactId)."""
        return f"{self.group_id}:{self.artifact_id}"

    @property
    def scope(self) -> str:
        """Get the dependency scope."""
        return self._dependency_dict.get("scope", "compile")

    @property
    def checksum(self) -> str | None:
        """Get the checksum."""

        # Some checksums have additional information after the hash, so we need to split and take the first part
        raw_checksum = self._dependency_dict.get("checksum")
        if raw_checksum:
            return raw_checksum.split()[0]

        return None

    @property
    def checksum_algorithm(self) -> str | None:
        """Get the checksum algorithm."""
        return self._dependency_dict.get("checksumAlgorithm")

    @property
    def classifier(self) -> str | None:
        """Get the classifier."""
        return self._dependency_dict.get("classifier")

    @property
    def resolved_url(self) -> str | None:
        """Get the resolved URL."""
        return self._dependency_dict.get("resolved")

    @property
    def children(self) -> list[dict[str, Any]]:
        """Get the children dependencies."""
        return self._dependency_dict.get("children", [])

    @property
    def boms(self) -> list[dict[str, Any]]:
        """Get the boms dependencies."""
        return self._dependency_dict.get("boms", [])

    @property
    def pom(self) -> dict[str, Any]:
        """Get the pom dependencies."""
        return self._dependency_dict.get("pom", {})

    def to_component(self) -> MavenComponent:
        """Convert to MavenComponent."""
        qualifiers: dict[str, str] = {"type": "jar"}
        if self.classifier:
            qualifiers["classifier"] = self.classifier
        purl = PackageURL(
            type="maven",
            namespace=self.group_id,
            name=self.artifact_id,
            version=self.version,
            qualifiers=qualifiers,
        )
        return MavenComponent(
            name=self.name,
            purl=purl.to_string(),
            version=self.version,
            scope=self.scope,
        )


class MavenLockfile:
    """A Maven lockfile.json file."""

    def __init__(self, lockfile_path: RootedPath, lockfile_data: dict[str, Any]) -> None:
        """Initialize a MavenLockfile."""
        self.lockfile_path = lockfile_path
        self.lockfile_data = lockfile_data
        self.dependencies = self._parse_dependencies()

    def _parse_dependencies(self) -> list[MavenDependency]:
        """Parse dependencies from lockfile data."""
        dependencies = []

        def parse_dependency_tree(dep_list: list[dict[str, Any]]) -> None:
            """Recursively parse dependency tree."""
            for dep_dict in dep_list:
                dep = MavenDependency(dep_dict)
                dependencies.append(dep)

                # recursively parse children
                if dep.children:
                    parse_dependency_tree(dep.children)

        parse_dependency_tree(self.lockfile_data.get("dependencies", []))
        return dependencies

    @classmethod
    def from_file(cls, lockfile_path: RootedPath) -> "MavenLockfile":
        """Create a MavenLockfile from a lockfile.json file."""
        with lockfile_path.path.open("r") as f:
            lockfile_data = json.load(f)

        return cls(lockfile_path, lockfile_data)

    def get_main_package(self) -> MavenComponent:
        """Get the main package as a MavenComponent."""
        group_id = self.lockfile_data["groupId"]
        artifact_id = self.lockfile_data["artifactId"]
        version = self.lockfile_data["version"]

        purl = PackageURL(
            type="maven",
            namespace=group_id,
            name=artifact_id,
            version=version,
            qualifiers={"type": "jar"},
        )

        return MavenComponent(
            name=f"{group_id}:{artifact_id}",
            purl=purl.to_string(),
            version=version,
            scope="compile",
        )

    def get_sbom_components(self, maven_stuff: dict[str, dict[str, Any]]) -> list[MavenComponent]:
        """Build the full flat SBOM component list from the merged download dict.

        The dict is computed once in _resolve_maven and reused here — no second traversal.
        Regular dependencies are handled separately via self.dependencies to preserve scope info.
        """
        dep_urls = {dep.resolved_url for dep in self.dependencies if dep.resolved_url}
        extras = {url: info for url, info in maven_stuff.items() if url not in dep_urls}
        return (
            [self.get_main_package()]
            + [dep.to_component() for dep in self.dependencies]
            + _components_from_dict(extras)
        )

    def get_dependencies_to_download(self) -> dict[str, dict[str, str | None]]:
        """Get dictionary of dependencies to download."""
        result = {}

        for dependency in self.dependencies:
            if dependency.resolved_url and dependency.resolved_url not in result:
                result[dependency.resolved_url] = {
                    "checksum": dependency.checksum,
                    "checksum_algorithm": dependency.checksum_algorithm,
                    "group_id": dependency.group_id,
                    "artifact_id": dependency.artifact_id,
                    "version": dependency.version,
                }
            _extract_pom_chain(dependency.pom, result)
            for bom in dependency.boms:
                _extract_pom_chain(bom, result)

        return result

    def get_plugins_to_download(self) -> dict[str, dict[str, str | None]]:
        """Get dictionary of plugins and their dependencies to download."""
        result = {}

        for plugin in self.lockfile_data.get("mavenPlugins", []):
            _extract_artifact(plugin, result)
            _extract_pom_chain(plugin.get("parent"), result)
            _extract_pom_chain(plugin.get("pom"), result)
            for bom in plugin.get("boms", []):
                _extract_pom_chain(bom, result)
            for dependency in plugin.get("dependencies", []):
                _extract_dependency(dependency, result)

        return result

    def get_boms_to_download(self) -> dict[str, dict[str, str | None]]:
        """Get dictionary of BOMs to download."""
        result = {}

        for bom in self.lockfile_data.get("boms", []):
            _extract_pom_chain(bom, result)

        return result

    def get_extensions_to_download(self) -> dict[str, dict[str, str | None]]:
        """Get dictionary of build extensions and their dependencies to download."""
        result = {}

        for extension in self.lockfile_data.get("extensions", []):
            _extract_artifact(extension, result)
            _extract_pom_chain(extension.get("parent"), result)
            _extract_pom_chain(extension.get("pom"), result)
            for bom in extension.get("boms", []):
                _extract_pom_chain(bom, result)
            for dependency in extension.get("dependencies", []):
                _extract_dependency(dependency, result)

        return result

    def get_parent_pom_to_download(self) -> dict[str, dict[str, str | None]]:
        result = {}

        pom = self.lockfile_data.get("pom", {})
        if pom:
            _extract_pom_chain(pom, result)

        return result
