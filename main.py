"""Module for generating constraints from the PyPA vulnerabilty repository."""

import argparse
import logging
from pathlib import Path

from settings import EXACT, EXCLUDE, MANUAL
from vulnerability_parser import VulnerbilityParser


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        "Command line arguments for the PyPA vulnerability parser."
    )

    parser.add_argument(
        "-r",
        "--repo",
        type=str,
        required=True,
        help="Path to the PyPA vulnerability git repository.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="constraints.txt",
        help="Path for the output constraints file.",
    )
    parser.add_argument(
        "-l",
        "--log",
        choices={"debug", "info", "warning", "error", "critical"},
        default="info",
        help="Logging level: debug, info, warning, error or critical.",
    )

    return parser.parse_args()


def get_repo_path(repo_path: str) -> Path:
    """Get and check the vulnerability repository path."""
    repo_path = Path(repo_path)
    if not repo_path.is_dir():
        raise RuntimeError(f"Vulnerability repository not found at: {repo_path}.")

    repo_path = repo_path / "vulns"
    if not repo_path.is_dir():
        raise RuntimeError(f"No vulnerabilities folder in the repository: {repo_path}.")

    return repo_path


def main() -> None:
    """Parses vulnerabilities into constraints."""
    arguments = parse_arguments()

    # Set up logging.
    logging.basicConfig(
        level=arguments.log.upper(),
        format="%(asctime)s | %(levelname)-7s | %(name)-20s | %(message)s",
        datefmt="%d-%m-%Y %H:%M:%S",
    )
    logger = logging.getLogger("VulnerabilityParser")
    logger.info("Start parsing vulnerabilities into constraints.")

    # Check the repository.
    logger.info("Checking repository path: %s", arguments.repo)
    repo_path = get_repo_path(arguments.repo)

    # Create and copnfigure the parser.
    logger.info("Reading vulnerabilities from: %s", repo_path)
    parser = VulnerbilityParser(repo_path)

    if EXACT:
        logger.info("Exact matches: %s", ", ".join(EXACT))
        parser.set_exact(EXACT)

    if EXCLUDE:
        logger.info("Excluding packages: %s", ", ".join(EXCLUDE))
        parser.set_exclude(EXCLUDE)

    if MANUAL:
        logger.info("Manual constaints: %s", ", ".join(MANUAL))
        parser.set_manual(MANUAL)

    logger.info("Processing the vulnerability repository.")
    parser.run()

    # Generate and write the constraints.
    logger.info("Creating constraints from vulnerabilities.")
    constraints = parser.make_constraints()

    logger.info("Writing constraints to: %s.", arguments.output)
    with open(arguments.output, "w", encoding="utf8") as out_file:
        out_file.write(constraints)

    logger.info("Finished parsing vulnerabilities into constraints.")


if __name__ == "__main__":
    main()
