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
from utils import AsyncLogger, estimate_block_number_by_time
from web3._utils.events import EventLogErrorFlags

__author__ = "yun"
__copyright__ = ""
__credits__ = ""
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


class TransferCostDetector(object):

    TransferMethodId = '0xa9059cbb'

    def __init__(self, _config_file: str, day: str):
        config = self.__load_config(_config_file)
        self.day = day

        # ---------- init logger --------------------
        if 'PathLog' not in config:
            raise KeyError('PathLog is not in config')
        self._logger = self.__set_logger(config['PathLog'])

        # ---------- init w3 object --------------------
        if 'RpcUrl' not in config:
            raise KeyError('RpcUrl is not in config')
        self._w3 = Web3(Web3.HTTPProvider(config['RpcUrl']))
        # self._w3 = Web3(Web3.AsyncHTTPProvider(config['RpcUrl']),
        #                 modules={'eth': (web3.eth.AsyncEth,), 'net': (web3.net.AsyncNet,)},
        #                 middlewares=[])
        with open(os.path.join('configs/abi_erc20.json'), 'r') as f:
            self._erc20_abi = json.load(f)
        pool_address = Web3.toChecksumAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48')
        self.pool_contract = self._w3.eth.contract(address=pool_address, abi=self._erc20_abi)

        # ---------- init w3 object --------------------
        if 'TransferCost' not in config:
            raise KeyError('TransferCost is not in config')
        cfg = config['TransferCost']
        self._num_blocks = cfg.get('NumBlocks', 1)

    @staticmethod
    def __load_config(_config_file: str) -> dict:
        try:
            if '.json' not in _config_file:
                raise Exception('config file is not json5')
            with open(_config_file) as f:
                config = json.load(f)
                # config = dict(config)
            return config
        except (FileNotFoundError, ValueError):
            raise
        except (Exception,):
            raise

    def __set_logger(self, path_log: str):
        try:
            if path_log != "" and (not os.path.isdir(path_log)):
                raise NotADirectoryError(f'invalid dir {path_log}')
            _logger = AsyncLogger(path=path_log,
                                  prefix=f'transfer_cost',
                                  namespace='TransferCost')
            _logger.file_name = os.path.join(path_log, f'transfer_cost_{self.day}.log')
            _logger.start_log()
            return _logger
        except (Exception,) as e:
            raise e

    def is_transfer(self, input_data):
        # transfer MethodID
        return input_data[:len(self.TransferMethodId)].lower() == self.TransferMethodId.lower()

    def search_transfer_1trans(self, trx, block):
        try:
            # trx = self._w3.eth.getTransaction(txid)
            if not self.is_transfer(trx['input']):
                return

            block_id = block['number']
            txid = trx.hash.hex()

            time.sleep(1)
            trx_receipt = self._w3.eth.getTransactionReceipt(txid)
            status = trx_receipt['status']
            if status == 0:  # Reverted
                self._logger.warning(json.dumps({'txid': txid, 'status': 'reverted', 'error': None}))
                return
            if status != 1:  # pending
                self._logger.warning(json.dumps({'txid': txid, 'status': 'pending', 'error': None}))
                return

            # status = 1: confirmed

            chain_id = trx.get('chainId', np.nan)
            # from_address = trx['from']
            # to_address = trx['to']
            gas_price_wei = trx['gasPrice']

            # maxFeePerGas: maximum total fee (base fee + priority fee) the sender is willing to pay per gas
            gas_fee_max_wei = trx.get('maxFeePerGas', np.nan)
            # maxPriorityFeePerGas: maximum fee the sender is willing to pay per gas above the base fee
            # (the maximum priority fee per gas)
            gas_fee_max_priority_wei = trx.get('maxPriorityFeePerGas', np.nan)
            # base fee
            gas_fee_base_wei = block['baseFeePerGas']
            # gas_price_wei = min(gas_fee_base_wei + gas_fee_max_priority_wei, gas_fee_max_wei)
            # assert gas_price_wei == min(gas_fee_base_wei + gas_fee_max_priority_wei, gas_fee_max_wei), ''

            # gas limit (maximum gas allocated for the transaction)
            gas_limit = trx['gas']
            # gas used (the amount of gas eventually used)
            # normal ETH transfers involve 21k gas units while contracts involve higher values
            gas_used = trx_receipt['gasUsed']  # returns 144197

            # total amount burnt from this transaction
            burnt_wei = gas_fee_base_wei * gas_used
            # transaction fee (total amount paid to the block producer for processing the transaction)
            transaction_fee_wei = gas_price_wei * gas_used
            # transaction type
            # https://docs.infura.io/infura/networks/ethereum/concepts/transaction-types
            trans_type = trx['type']

            # pool_address = Web3.toChecksumAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48')
            # pool_contract = self._w3.eth.contract(address=pool_address, abi=self._erc20_abi)
            time.sleep(1)
            logs = self.pool_contract.events.Transfer().processReceipt(trx_receipt, EventLogErrorFlags.Warn)
            logs_summary = list()
            for log in logs:
                transfer_token = log.address
                transaction_type = log.event
                sender_address = log.args['from']
                destination_address = log.args['to']
                amount = log.args['value']
                logs_summary.append({'type': transaction_type, 'from': sender_address, 'to': destination_address,
                                     'transfer_token': transfer_token, 'amount_wei': amount})

            transfer = {'txid': txid, 'block_id': block_id, 'chain_id': chain_id, 'status': 'confirmed',
                        'trans_type': trans_type,
                        'gas_price_wei': gas_price_wei, 'gas_fee_base_wei': gas_fee_base_wei,
                        'gas_fee_max_wei': gas_fee_max_wei, 'gas_fee_max_priority_wei': gas_fee_max_priority_wei,
                        'gas_limit': gas_limit, 'gas_used': gas_used,
                        'burnt_wei': burnt_wei, 'transaction_fee_wei': transaction_fee_wei, 'logs': logs_summary,
                        'error': None}

            print('{}: {}, {}'.format(pd.Timestamp.now(), block_id, txid))
            self._logger.info(json.dumps(transfer))
            return

        except (Exception,) as e:
            self._logger.error(json.dumps({'txid': trx.hash.hex(), 'error': str(e)}))
            return

    def search_transfer(self):
        # end_block_id = self._w3.eth.get_block_number()
        # start_block_id = end_block_id - self._num_blocks
        start_block_id = estimate_block_number_by_time(pd.to_datetime(self.day).timestamp())
        end_block_id = estimate_block_number_by_time((pd.to_datetime(self.day) + pd.Timedelta('1D')).timestamp())
        # start_block_id = 16308190
        # end_block_id = 16308192

        for block_id in range(start_block_id, end_block_id + 1):
            block = self._w3.eth.get_block(block_id, True)
            if block is None:
                continue
            if len(block['transactions']) == 0:
                continue

            for i, trx in enumerate(block['transactions']):
                # t = threading.Thread(target=asyncio.run, args=(self.search_transfer_1trans(txid, block),))
                # t.start()
                t = threading.Thread(target=self.search_transfer_1trans, args=(trx, block))
                t.start()

        # self._logger.stop_log()


if __name__ == '__main__':
    day = '2023-01-01'
    if len(sys.argv) >= 2:
        day = sys.argv[1]

    config_file = 'configs/test_config.json'

    d = TransferCostDetector(config_file, day)
    # asyncio.run(d.search_transfer())
    d.search_transfer()
