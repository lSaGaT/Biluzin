#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""biluzim - launcher executavel (instalavel em /usr/local/bin ou ~/.local/bin)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from biluzim.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
