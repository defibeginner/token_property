#!/usr/bin/env python

"""
main script of permit
"""

import asyncio
import json

import aiohttp
from web3 import Web3

from web3.eth import AsyncEth

import os
import re
import warnings
import copy
import pprint
import requests
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
from eip712_structs import make_domain
from eip712_structs import EIP712Struct, String, Uint, Address

from sklearn.model_selection import ParameterGrid

__author__ = "yun"
__copyright__ = ""
__credits__ = ""
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""

warnings.filterwarnings("ignore")

pp = pprint.PrettyPrinter()


def value_equal(x, y):
    """
    transfer amount is a large integer, and is rounded up
    so for example, transfer amount 47256182151634140 might become 47256182151634139 when arrives at the receiver
    we still think the receiver receives the full amount
    so we need this function value_equal()

    :param x:
    :param y:
    :return:
    """
    return -1 <= x - y <= 1


def values_equal(x, y):
    if len(x) != len(y):
        return False
    for i in range(len(x)):
        if not value_equal(x[i], y[i]):
            return False
    return True


def get_fee_value(amount_out, amount_trans):
    """
    sim_result = [{'amount': 18789507722288, 'amount_out': 18789507722288, 'amount_in': 9582648938367},
                  {'amount': 7527122227138, 'amount_out': 7527122227138, 'amount_in': 3838832335841},
                  {'amount': 145410737490143, 'amount_out': 145410737490143, 'amount_in': 74159476119973},
                  {'amount': 45833242489386, 'amount_out': 45833242489386, 'amount_in': 23374953669587},
                  {'amount': 7526989113272, 'amount_out': 7526989113272, 'amount_in': 3838764447769}
                  ]

    :param amount_out:
    :param amount_trans:
    :return: fee_type, fee, fee_ratio, exempt_found, error_message
    """
    try:
        fees = []
        fee_ratios = []
        exempt_found = 'No'
        for i in range(len(amount_out)):
            # get fee value
            # TODO: a potential error: 'Python int too large to convert to C long'
            fee = amount_out[i] - amount_trans[i] if amount_out[i] > amount_trans[i] else amount_trans[i] - amount_out[i]
            # get fee ratio
            fee_ratio = np.round(fee / amount_trans[i], 9)  # TODO hardcoded 9 decimal points
            if fee_ratio > 1.0:
                raise Exception(f'fee_ratio greater than 1: {fee_ratio}')
            # a fee exempt found
            if value_equal(fee, 0):
                exempt_found = 'Yes'
            else:
                fees.append(fee)
                fee_ratios.append(fee_ratio)
        fee_uniq = set(fees)
        fee_ratio_uniq = set(fee_ratios)
        # special cases
        if len(fees) == 0:
            return 'Unknown', str(fees[0]), str(fee_ratios[0]), exempt_found, 'only exempt trx simulated'
        if len(amount_trans) == 1:
            return 'Unknown', str(fees[0]), str(fee_ratios[0]), exempt_found, '1 trx'
        if len(fee_uniq) == 1 and len(fee_ratio_uniq) == 1:
            return 'Unknown', str(fees[0]), str(fee_ratios[0]), exempt_found, 'all trx are same'
        # fixed
        if len(fee_uniq) == 1 and len(fee_ratio_uniq) > 1:
            return 'Fixed', str(fees[0]), '', exempt_found, ''
        # franctional
        if len(fee_uniq) > 1 and len(fee_ratio_uniq) == 1:
            return 'Fractional', '', str(fee_ratios[0]), exempt_found, ''
        # not fot
        # if len(fee_uniq) > 1 and len(fee_ratio_uniq) > 1:
        return 'Unknown', str(fee_uniq), str(fee_ratio_uniq), exempt_found, 'fee is changing'
    except (Exception,) as e:
        return 'Unknown', '', '', '', str(e)


def is_fot(sim_result) -> dict:
    """
    inclusive fee-on-transfer: receiver receives fewer amounts
    exclusive fee-on-transfer: sender outputs more amounts

    :param sim_result:
    :return:
    """
    if len(sim_result) == 0:
        return {'is_fot': 'Unknown', 'fot_type': '', 'fee_type': '',
                'sender_fee': '', 'sender_fee_ratio': '',
                'receiver_fee': '', 'receiver_fee_ratio': '',
                'fee_exempt_found': '', 'error': 'no trx'}

    amount = [res['amount'] for res in sim_result]
    amount_out = [res['amount_out'] for res in sim_result]
    amount_in = [res['amount_in'] for res in sim_result]
    zeros = [0 for _ in sim_result]

    if values_equal(amount_out, zeros) or values_equal(amount_in, zeros):
        return {'is_fot': 'Unknown', 'fot_type': '', 'fee_type': '',
                'sender_fee': '', 'sender_fee_ratio': '',
                'receiver_fee': '', 'receiver_fee_ratio': '',
                'fee_exempt_found': '', 'error': 'amount is 0'}

    out_amount_same = values_equal(amount_out, amount)
    in_amount_same = values_equal(amount_in, amount)

    # is not FoT
    if out_amount_same and in_amount_same:
        return {'is_fot': 'No', 'fot_type': '', 'fee_type': '',
                'sender_fee': '', 'sender_fee_ratio': '',
                'receiver_fee': '', 'receiver_fee_ratio': '',
                'fee_exempt_found': '', 'error': ''}

    # is FoT
    if out_amount_same and not in_amount_same:
        fot_type = 'Inclusive'
        fee_type, receiver_fee, receiver_fee_ratio, exempt_found, e = get_fee_value(amount_in, amount)
        sender_fee, sender_fee_ratio = '', ''
    elif not out_amount_same and in_amount_same:
        fot_type = 'Exclusive'
        fee_type, sender_fee, sender_fee_ratio, exempt_found, e = get_fee_value(amount_out, amount)
        receiver_fee, receiver_fee_ratio = '', ''
    else:
        fot_type = 'Inclusive&Exclusive'
        fee_type1, receiver_fee, receiver_fee_ratio, exempt_found1, e = get_fee_value(amount_in, amount)
        fee_type2, sender_fee, sender_fee_ratio, exempt_found2, _ = get_fee_value(amount_out, amount)
        fee_type = f'{fee_type1} | {fee_type2}'
        exempt_found = exempt_found1 or exempt_found2
    return {'is_fot': 'Yes', 'fot_type': fot_type, 'fee_type': fee_type,
            'sender_fee': sender_fee, 'sender_fee_ratio': sender_fee_ratio,
            'receiver_fee': receiver_fee, 'receiver_fee_ratio': receiver_fee_ratio,
            'fee_exempt_found': exempt_found, 'error': e}


class FeeOnTransferDetector(object):

    RPC_URL = 'http://localhost:8545'

    API_KEY = 'PR8IBWAK7QQ37TCCBC1JIIJ9I8JFSP15M9'
    ETH_API_URL = 'https://api.etherscan.io/api'

    TransferFuncSelector = '0xa9059cbb'

    def __init__(self):
        self.w3 = Web3(Web3.AsyncHTTPProvider(self.RPC_URL), modules={'eth': (AsyncEth,)}, middlewares=[])

        with open('configs/abi_erc20.json') as f:
            abi = json.load(f)
        self.erc20 = self.w3.eth.contract(address=None, abi=abi)

    def get_history_transactions(self, token_address, page=1, num_trans=1):
        """
        example
        https://api.etherscan.io/api?module=account&action=txlist&address=0xddbd2b932c763ba5b1b7ae3b362eac3e8d40121a&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey=YourApiKeyToken

        :param token_address:
        :param page:
        :param num_trans:
        :return:
        """
        try:
            params = {'module': 'account',
                      'action': 'txlist',
                      'address': token_address,
                      'startblock': 0,
                      'endblock': 99999999,  # TODO: hardcoded startblock and endblock, is there an issue here?
                      'page': page,
                      'offset': num_trans,
                      'sort': 'desc',
                      'apikey': self.API_KEY}
            r = requests.get(url=self.ETH_API_URL, params=params)
            data = r.json()
            # pp.pprint(data)

            if data['status'] == 0:
                raise Exception('fail get transactions {}'.format(data['result']))

            return data['result'], None
        except (Exception,) as e:
            return None, e

    def is_transfer(self, input_data):
        # input_data = tx['input']
        return input_data[:len(self.TransferFuncSelector)].lower() == self.TransferFuncSelector.lower()

    def get_trx_info(self, token_address, tx, tx_rcpt):
        """
        :param token_address:
        :param tx: = web3.eth.get_transaction(txid)
        :param tx_rcpt: = web3.eth.get_transaction_receipt(txid)
        :return:
        """
        try:
            txid = tx['hash']
            gas_limit = int(tx['gas'])
            block_number = int(tx['blockNumber'])
            """
            one of "from" or "to" (usually is "to") is the token_address
            so we will find "from" and "to" from the tx_rcpt
            """
            # from_ = tx['from']
            # to = tx['to']
            logs = self.erc20.events.Transfer().processReceipt(tx_rcpt, EventLogErrorFlags.Warn)
            assert len(logs) == 1, 'multiple transaction_receipt logs'
            log = logs[0]
            # block_number = log.blockNumber
            # transaction_type = log.event  # this will be 'transfer'
            # token_address = log.address
            # txid = log.transactionHash
            from_ = log.args['from']
            to = log.args['to']
            amount = log.args['value']
            if from_ == to or from_ == token_address or to == token_address:
                raise Exception('invalid from and to address')
            ret = {
                'txid': txid,
                'token': token_address,
                'gas_limit': gas_limit,
                'block_number': block_number,
                'from': from_,
                'to': to,
                'amount': amount,
            }
            return ret, None
        except (Exception,) as e:
            return None, e

    async def get_history_transfers(self, token_address, num_trans):
        """
        find the [num_trans] historical transfers of a given token_address
        :param token_address:
        :param num_trans:
        :return: transfers, list of dict
            [{'txid': txid, 'token': token_address, 'gas_limit': gas_limit, 'block_number': block_number,
              'from': from_, 'to': to, 'amount': amount}]
        """
        try:
            transfers = []
            page = 0
            max_page = 20
            while page < max_page:
                # TODO: hardcoded num_trans=50
                txs, e = self.get_history_transactions(token_address, page=page, num_trans=50)
                if e is not None:
                    raise e
                for i, tx in enumerate(txs):
                    txid = tx['hash']
                    # get transaction
                    # tx = await self.w3.eth.get_transaction(txid)
                    # get transaction receipt
                    tx_rcpt = await self.w3.eth.get_transaction_receipt(txid)
                    if not self.is_transfer(tx['input']):
                        # we only need transfers
                        continue
                    if tx_rcpt['status'] != 1:
                        # require transaction is confirmed (filled)
                        continue
                    trx_info, e = self.get_trx_info(token_address, tx, tx_rcpt)
                    if e is not None:
                        continue
                    # we require the tx is a filled transfer
                    transfers.append(trx_info)
                    if len(transfers) == num_trans:
                        return transfers, None
            return transfers, None

        except (Exception,) as e:
            return None, e

    # ------------------------------------------------------------------------------------------------------------------

    async def call_many(self, session, txs, block_number):
        params = [[{"transactions": txs}], {"blockNumber": Web3.toHex(block_number), "transactionIndex": 0}]
        request = {"jsonrpc": "2.0", "method": "eth_callMany", "params": params, "id": 1}
        async with session.post("http://localhost:8545", json=request,
                                headers={"Content-Type": "application/json"}) as resp:
            response = await resp.json()
        return response

    def prepare_balance_of(self, token, address, block_gas):
        calldata = self.erc20.encodeABI(fn_name='balanceOf', args=[address])
        tx = {
            'data': calldata,
            'gas': '0x0',
            'maxPriorityFeePerGas': '0x0',
            'maxFeePerGas': Web3.toHex(block_gas),
            'to': token,
            'value': '0x0'
        }
        return tx

    def prepare_transfer(self, token, from_, to, amount, block_gas, gas_limit):
        calldata = self.erc20.encodeABI(fn_name='transfer', args=[to, amount])
        tx = {
            'data': calldata,
            'gas': Web3.toHex(gas_limit),  # TODO: ask Rob
            'maxPriorityFeePerGas': '0x0',
            'maxFeePerGas': Web3.toHex(block_gas),
            'from': from_,
            'to': token
        }
        return tx

    async def sim_transfer(self, session, block_number, token, from_, to, amount, gas_limit):
        try:
            block = await self.w3.eth.get_block(block_number)
            base_fee = block['baseFeePerGas']
            get_sender_balance = self.prepare_balance_of(token, from_, base_fee)
            get_receiver_balance = self.prepare_balance_of(token, to, base_fee)
            transfer = self.prepare_transfer(token, from_, to, amount, base_fee, gas_limit)
            txs = [get_sender_balance,
                   get_receiver_balance,
                   transfer,
                   get_sender_balance,
                   get_receiver_balance]
            callmany = await self.call_many(session, txs, block_number)
            return callmany, None
        except (Exception,) as e:
            return None, e

    async def simulate_transfer(self, trx_info):
        """
        :param trx_info: dict with keys {'amount', 'block_number', 'from', 'gas_limit', 'to', 'token', 'txid'}
        :return:
        """
        try:
            async with aiohttp.ClientSession() as session:
                result, e = await self.sim_transfer(session,
                                                    block_number=trx_info['block_number'],
                                                    token=trx_info['token'],
                                                    from_=trx_info['from'],
                                                    to=trx_info['to'],
                                                    amount=trx_info['amount'],
                                                    gas_limit=trx_info['gas_limit'])
                if e is not None:
                    raise e
            # print(
            #     f"""
            #     amount = {trx_info['amount']}
            #     from_ = '{trx_info['from']}'
            #     to = '{trx_info['to']}'
            #     token = '{trx_info['token']}'
            #     block_number = {trx_info['block_number']}"""
            # )
            # pp.pprint(result)
            """
            {'id': 1,
             'jsonrpc': '2.0',
             'result': [[{'value': '0000000000000000000000000000000000000000000000000000000000000000'},
                         {'value': '0000000000000000000000000000000000000000000000000000000000000001'},
                         {'value': '0000000000000000000000000000000000000000000000000000114ba394fc2a'}]]}
            """
            # process the output
            data = result['result'][0]
            amount = trx_info['amount']
            sender_bal_before = Web3.toInt(hexstr=data[0]['value'])
            sender_bal_after = Web3.toInt(hexstr=data[3]['value'])
            receiver_bal_before = Web3.toInt(hexstr=data[1]['value'])
            receiver_bal_after = Web3.toInt(hexstr=data[4]['value'])
            amount_out = sender_bal_before - sender_bal_after
            amount_in = receiver_bal_after - receiver_bal_before
            # print('-' * 100)
            # pp.pprint(trx_info)
            # print(f'transfer amount = {amount}')
            # print(f'amount_out_from_sender = {amount_out} {amount_out / amount}')
            # print(f'amount_into_receiver = {amount_in} {amount_in / amount}')
            ret = {'amount': amount,
                   'amount_out': amount_out,
                   'amount_in': amount_in,
                   'txid': trx_info['txid']}
            return ret, None
        except (Exception,) as e:
            return None, e

    @staticmethod
    def get_sim_params(trx_info):
        """
        given each transfer, run 2 simulation with different amount
            first simulation: use the original transferred amount
            second simulation: use half the transferred amount
        :param trx_info: dict with keys {'amount', 'block_number', 'from', 'gas_limit', 'to', 'token', 'txid'}
        :return:
        """
        try:
            trx_info2 = copy.deepcopy(trx_info)
            trx_info2['amount'] = int(trx_info['amount'] / 2)
            return [trx_info, trx_info2], None
        except (Exception,) as e:
            return None, e

    async def __is_fot_token(self, token_address, num_trans):
        try:
            transfers, e = await self.get_history_transfers(token_address, num_trans=num_trans)
            if e is not None:
                raise e

            sim_result = []
            for trx in transfers:
                trx_for_sim, e = self.get_sim_params(trx)
                if e is not None:
                    continue
                for trx2 in trx_for_sim:
                    res, e = await self.simulate_transfer(trx2)
                    if e is not None:
                        continue
                    sim_result.append(res)
                    # await asyncio.sleep(0.1)
            # ------------------------------

            fot_result = is_fot(sim_result)
            fot_result['token'] = token_address
            fot_result['sim_result'] = sim_result

            return fot_result

        except (Exception,) as e:
            return {'token': token_address, 'error': str(e)}

    async def is_fot_token(self, token_address):
        """
        a two-step simulation method:
        step 1: a quick simulation with 1 or 2 transfers. goal is quickly know if the token is FoT token
            but the fee value and fee type may not be correct
        step 2: a deep search with N (N is as large as possible). goal is to find the fee value and fee type
            to the best knowledge

        :param token_address:
        :return:
        """
        # step 1: a quick search
        res1 = await self.__is_fot_token(token_address, num_trans=2)
        if res1.get('is_fot', 'No') == 'No':
            return res1
        # step 2: a deep search (only for FoT token)
        return await self.__is_fot_token(token_address, num_trans=20)

    async def main(self):
        # -------------------- Option 1: raw data from historical trans ----------------------------------------
        # x = pd.read_csv('configs/token_list_0xapi_eth.csv')
        # # x = pd.read_csv('configs/token_registry_202302171614.csv')
        # token_list = x[['address']].copy()
        #
        # df = []
        # days = pd.date_range('2022-12-11', '2023-01-10', freq='1D')
        # for day in days:
        #     filename = 'results/trans_cost/transfer_cost_{}.csv'.format(day.date())
        #     x = pd.read_csv(filename)
        #     x = x[['transfer_token']]
        #     df.append(x)
        # df = pd.concat(df)
        # token_list2 = np.array([str(t) for t in df.transfer_token.values if isinstance(t, str)])
        #
        # tokens = np.concatenate([token_list.address.values, token_list2])
        # token_list = np.unique(tokens)
        #
        # # token_list = ['0x44Fd539Eb6fBe1f28be4fE6608Fa78CF7ff497F3']
        # n_tokens = len(token_list)

        # -------------------- Option 2: processed data ----------------------------------------
        x = pd.read_csv('results/fee_on_transfer/fee_on_transfer_3.csv')
        token_list = x[x.is_fot == 'Yes'].address.values
        n_tokens = len(token_list)

        # ------------------------------------------------------------
        _logger = AsyncLogger(path='results/fee_on_transfer',
                              prefix=f'fot',
                              namespace='fot')
        _logger.file_name = os.path.join('results/fee_on_transfer', f'fee_on_transfer.log')
        _logger.start_log()

        n_fot = 0
        for i in range(n_tokens):
            result = await self.is_fot_token(token_list[i])
            _logger.info(json.dumps(result))
            if result.get('is_fot', 'No') == 'Yes':
                n_fot += 1
                print(f'{i} / {n_tokens}: {n_fot}',
                      result.get('token', ''),
                      result.get('is_fot', ''),
                      result.get('fot_type', ''),
                      result.get('fee_type', ''),
                      result.get('fee_exempt_found', ''),
                      result.get('error', ''),
                      )
            else:
                print(f'{i} / {n_tokens}: {n_fot}')
            # await asyncio.sleep(0.1)

        await asyncio.sleep(10)
        _logger.stop_log()

    async def test(self):
        # result = await self.__is_fot_token('0x79add5ef078345f52e156ad8337a8441e0229bfc', 2)
        # result = await self.__is_fot_token('0xc5a9bc46a7dbe1c6de493e84a18f02e70e2c5a32', 20)  # WCI
        # result = await self.__is_fot_token('0x0040fd6b4Cb50003eA9Fc0651592a113ccBA45bc', 2)
        # result = await self.is_fot_token('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')  # USDC
        result = await self.is_fot_token('0x0040fd6b4Cb50003eA9Fc0651592a113ccBA45bc')
        pp.pprint(result)


def test_is_fot():
    # case 1: some simulation transfers are from exempt account so fee is 0
    sim_result = [{'amount': 23491068090397,
                   'amount_in': 11980444726103,
                   'amount_out': 23491068090397,
                   'txid': '0xe087dd97f3f6d80a6277058038b943266d2d3fe888e7d20e0d18e9e30e2f29ad'},
                  {'amount': 3345520000000,
                   'amount_in': 3345520000000,
                   'amount_out': 3345520000000,
                   'txid': '0xecd7168f577019e02c006c5c4cb79cd0ceafabd7f8c5286ebabcd4e56b5779d9'},
                  {'amount': 2733043724060,
                   'amount_in': 1393852299271,
                   'amount_out': 2733043724060,
                   'txid': '0x3d459035c31458cc7c76aec9aec777f15014e6ab2398f30774e9146797170b76'},
                  ]
    res = is_fot(sim_result)
    pp.pprint(res)


if __name__ == '__main__':
    d = FeeOnTransferDetector()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(d.main())
    loop.close()
