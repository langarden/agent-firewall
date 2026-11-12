# -*- coding: utf-8 -*-
"""Demo entry point: `agent-firewall-demo` console script."""

from .demo import run_demo


def main() -> None:
    for row in run_demo():
        print(row)


if __name__ == "__main__":
    main()