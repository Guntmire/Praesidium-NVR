"""Entry point for the NVR application."""

from configuration import load_default
from api import start_server


def main() -> None:
    config = load_default()
    start_server(config)


if __name__ == "__main__":
    main()
