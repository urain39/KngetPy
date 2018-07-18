#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from . import base

if __name__ == '__main__':
    try:
        base.main((None,))
    except (KeyboardInterrupt, EOFError):
        sys.exit(base._NO_ERROR)
