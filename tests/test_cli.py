import subprocess
import sys

import pytest
from pytest import CaptureFixture

from wlanscope.cli import PROJECT_NAME, PROJECT_TAGLINE, main
from wlanscope.version import __version__


def test_help_describes_available_cli(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_result:
        main(["--help"])

    output = capsys.readouterr().out

    assert exit_result.value.code == 0
    assert PROJECT_NAME in output
    assert PROJECT_TAGLINE in output
    assert "--version" in output


def test_version_uses_package_metadata(capsys: CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_result:
        main(["--version"])

    assert exit_result.value.code == 0
    assert capsys.readouterr().out.strip() == f"{PROJECT_NAME} {__version__}"


@pytest.mark.parametrize("option", ["--help", "--version"])
def test_module_entry_point(option: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wlanscope", option],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert PROJECT_NAME in result.stdout
    assert result.stderr == ""


def test_module_entry_point_without_arguments() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wlanscope"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_cli_without_arguments_succeeds(capsys: CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert capsys.readouterr().out == ""
