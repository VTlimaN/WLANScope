from importlib.metadata import PackageNotFoundError, version


def installed_version() -> str:
    try:
        return version("wlanscope")
    except PackageNotFoundError:
        return "0+unknown"


__version__ = installed_version()
