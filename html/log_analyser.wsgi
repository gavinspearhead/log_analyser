#!/usr/bin/python3

import sys
sys.stdout = sys.stderr
sys.path.insert(0, '/opt/log_analyser/html')

from log_analyser import app as application