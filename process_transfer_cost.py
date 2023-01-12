#!/usr/bin/env python

"""
main script of pricing api
"""

import os
import pprint
import sys
import time
import flask
import json
from enum import IntEnum
import asyncio
import requests
import threading
import numpy as np
import pandas as pd
import web3
from web3 import eth, net
from web3 import Web3, exceptions
from utils import AsyncLogger
from web3._utils.events import EventLogErrorFlags

__author__ = "yun"
__copyright__ = ""
__credits__ = ""
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


def read_log(_filename):
    with open(_filename) as f:
        for line in f:
            line = line[:-1]
            line = line[line.find('{'):]
            transfer = json.loads(line)


if __name__ == '__main__':
    filename = 'results/transfer_cost_2023-01-01.log'
