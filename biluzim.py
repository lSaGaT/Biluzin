#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""biluzim - launcher executavel (instalavel em /usr/local/bin ou ~/.local/bin)."""
import os
import sys

# realpath resolve o symlink criado pelo install.sh (o pacote vive no clone)
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from biluzim.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
