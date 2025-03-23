"""Module for storing vulnerability information."""

import logging
import re

from packaging.version import VERSION_PATTERN, InvalidVersion, Version


class Vulnerabilities:
    """Class for storing vulnerability information."""

    def __init__(self) -> None:
        self._log = logging.getLogger(self.__class__.__name__)
        self._vulnerabilities = {}
        self._iter_keys = None

    def add(
        self, package: str, identifier: str, source: str, versions: list, fixes: list
    ) -> None:
        """Add a package vulnerability."""
        self._log.debug("Adding package: %s -- vulnerability: %s", package, identifier)

        # Store vulnerability metadata as list of dicts.
        if package not in self._vulnerabilities:
            self._vulnerabilities[package] = []

        self._vulnerabilities[package].append(
            {
                "identifier": identifier,
                "source": source,
                "versions": versions,
                "fixes": fixes,
            }
        )

    def get_vulnerable_versions(self, package: str) -> tuple:
        """Retrieve all vulnerable versions and metadata."""
        if package not in self._vulnerabilities:
            raise KeyError(f"Unknown package: {package}")

        source = package
        versions = []
        identifiers = []
        for vulnerability in self._vulnerabilities[package]:
            versions.extend(vulnerability["versions"])
            identifiers.append(vulnerability["identifier"])

        return set(versions), identifiers, source

    def get_highest_fix(self, package: str) -> tuple:
        """Retieve highest vulnerable version and associated metadata."""
        if package not in self._vulnerabilities:
            raise KeyError(f"Unknown package: {package}")

        source = None
        highest_fix = "0.0.0"
        identifier = None

        # Find the highest fixed version.
        for vulnerability in self._vulnerabilities[package]:
            fix = self._get_highest_version(vulnerability["fixes"])

            if self._is_higher_version(fix, highest_fix):
                highest_fix = fix
                identifier = vulnerability["identifier"]
                source = (
                    vulnerability["source"].parent.name,
                    vulnerability["source"].name,
                )

        # No fixed version available.
        if highest_fix == "0.0.0":
            self._log.warning("Package %s has no fixed versions.", package)
            return None, None, None

        return highest_fix, identifier, source

    def _get_highest_version(self, versions: list) -> str:
        """Get highest version from a set of versions."""
        highest = "0.0.0"
        for version in versions:
            if self._is_higher_version(version, highest):
                highest = version

        return highest

    @staticmethod
    def _convert_version(version: str) -> Version:
        """Convert to version string to Version object."""
        try:
            return Version(version)

        except InvalidVersion:
            if m := re.search(VERSION_PATTERN, version, re.VERBOSE | re.IGNORECASE):
                return Version(m.group(0))

        except TypeError as error:
            raise RuntimeError(f"Version is not of type string: {version}.") from error

        raise ValueError(f"Version {version} is not a valid version number.")

    def _is_higher_version(self, current: str, target: str) -> bool:
        """Checks version number is higher or not."""
        current = self._convert_version(current)
        target = self._convert_version(target)
        return current > target

    def __iter__(self):
        """Start iterating over packages."""
        self._iter_keys = list(self._vulnerabilities)
        return self

    def __next__(self):
        """Get the next package."""
        if self._iter_keys:
            return self._iter_keys.pop(0)
        raise StopIteration
