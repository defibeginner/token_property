#!/usr/bin/env python

"""
main script of permit
"""

import os
import re
import warnings
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

__author__ = "yun"
__copyright__ = ""
__credits__ = ""
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


pp = pprint.PrettyPrinter()


def find_function_in_source_code(source_code, function_name):
    """
    function must be implemented instead of being imported from interface

    :param source_code:
    :param function_name:
    :return:
    """
    # i = source_code.find(f'function {function_name}(')
    for m in re.finditer(f'function {function_name}', source_code):
        left = m.start()
        right = source_code[left:].find(';')
        if right == -1:
            continue
        left_bracket = source_code[left:left+right].find('{')
        # right_bracket = source_code[i:i+j].find('}')
        #
        if left_bracket != -1:
            return True
    return False


class PermitDetector(object):

    API_KEY = 'PR8IBWAK7QQ37TCCBC1JIIJ9I8JFSP15M9'
    ETH_API_URL = 'https://api.etherscan.io/api'

    RPC_URL = "https://eth-mainnet.alchemyapi.io/v2/sBFFXcfLNdXl-Ym71hIwfpvhzAtdLE2e"

    # final signature starts with uint16(0x1901)
    SignatureInitial = ["0x1901", "\\x19\\x01", "\\x19\\\\x01"]

    def __init__(self, _config_file: str):
        config = self.__load_config(_config_file)
        if 'Permit' not in config:
            raise KeyError('Permit is not in config')
        cfg = config['Permit']

        self.w3 = Web3(Web3.HTTPProvider(self.RPC_URL))

        # ---------- init logger --------------------
        if 'PathLog' not in cfg:
            raise KeyError('PathLog is not in config')
        self._logger = self.__set_logger(cfg['PathLog'])

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

    @staticmethod
    def __set_logger(path_log: str):
        try:
            if path_log != "" and (not os.path.isdir(path_log)):
                raise NotADirectoryError(f'invalid dir {path_log}')
            _logger = AsyncLogger(path=path_log,
                                  prefix=f'permit',
                                  namespace='permit')
            _logger.file_name = os.path.join(path_log, f'permit.log')
            _logger.start_log()
            return _logger
        except (Exception,) as e:
            raise e

    def _check_abi(self, address):
        params = {'module': 'contract',
                  'action': 'getabi',
                  'address': address,
                  'apikey': self.API_KEY}
        r = requests.get(url=self.ETH_API_URL, params=params)
        data = r.json()
        # pp.pprint(data)
        abi = json.loads(data['result'])
        found_permit_in_abi = False
        for attr in abi:
            n = attr.get('name', '').lower()
            if n == 'permit' or n == 'permit_typehash':
                found_permit_in_abi = True
                break
        return found_permit_in_abi

    def _get_source_code(self, address):
        try:
            params = {'module': 'contract',
                      'action': 'getsourcecode',
                      'address': address,
                      'apikey': self.API_KEY}
            r = requests.get(url=self.ETH_API_URL, params=params)
            data = r.json()
            # pp.pprint(data)
            if len(data['result']) > 1:
                raise Exception('data["result"] len>1')
            if len(data['result']) == 0:
                raise Exception('failed to get source code')
            if 'SourceCode' not in data['result'][0]:
                raise Exception('failed to get source code')
            if 'ABI' not in data['result'][0]:
                raise Exception('failed to get ABI')
            source_code = data['result'][0]['SourceCode'].lower()
            abi = data['result'][0]['ABI']
            abi = json.loads(abi)
            constructor_argument = data['result'][0]['ConstructorArguments'].lower()

            is_proxy = False
            for attr in abi:
                n = attr.get('name', '').lower()
                if n == 'implementation':
                    is_proxy = True
                    break
            return source_code, abi, constructor_argument, is_proxy, None
        except (Exception,) as e:
            return None, None, None, None, e

    def _find_implement_contract(self, is_proxy, source_code, constructor_argument, token_address):
        try:
            if not is_proxy:
                return '', None
            # ---------- step 1: search "implementation slot" from source code ----------
            # find implementation slot
            i = source_code.find("implementation_slot =")
            implementation_slot = ''
            if i != -1:
                k = source_code[i:].find('0x')
                j = source_code[i:].find(';')
                if j != -1 and k != -1:
                    implementation_slot = source_code[i + k:i + j]
            if implementation_slot == '':
                i = source_code.find('implementation_storage =')
                implementation_slot = ''
                if i != -1:
                    k = source_code[i:].find('0x')
                    j = source_code[i:].find(';')
                    if j != -1 and k != -1:
                        implementation_slot = source_code[i + k:i + j]

            if implementation_slot != '':
                # find implementation contract
                impl_contract = self.w3.toHex(
                    self.w3.eth.get_storage_at(
                        Web3.toChecksumAddress(token_address),
                        implementation_slot,
                    )
                )
                impl_contract = '0x' + impl_contract[-(len(token_address)-2):]
                return impl_contract, None
            # ---------- step 2: decode constructor argument ----------
            # impl_contract = '0x' + constructor_argument[-(len(token_address)-2):]
            raise Exception('impl in const_arg')
        except (Exception,) as e:
            return '', e

    @staticmethod
    def _find_permit_func(source_code):
        known_func_names = ['permit']
        for func_name in known_func_names:
            if find_function_in_source_code(source_code, func_name):
                return True
        return False

    @staticmethod
    def _find_domain_separator_func(source_code):
        # SYN, 0x0f2d719407fdbeff09d87557abb7232601fd9f29, _buildDomainSeparator(), _domainseparatorv4()
        # 0x3b484b82567a09e2588a13d54d032153f0c0aee0, _buildDomainSeparator(), _domainseparatorv4()
        known_func_names = ['domain_separator', 'eip712_domain_separator', 'getdomainseperator', '_domainseparatorv4']
        for func_name in known_func_names:
            if find_function_in_source_code(source_code, func_name):
                return True
        return False

    @staticmethod
    def _find_nonces_func(source_code):
        known_func_names = ['nonces', 'nonce']
        for func_name in known_func_names:
            if find_function_in_source_code(source_code, func_name):
                return True
        return False

    @staticmethod
    def _find_signature(source_code):
        known_initials = ["0x1901", "\\x19\\x01", "\\x19\\\\x01"]
        for sig in known_initials:
            if sig in source_code:
                return True
        return False

    @staticmethod
    def _find_nonces(source_code):
        known_names = ["nonces", "nonce"]
        for name in known_names:
            if name in source_code:
                return True
        return False

    @staticmethod
    def _find_domain_separator(source_code):
        known_names = ["eip712domain", "domain_separator"]
        for name in known_names:
            if name in source_code:
                return True
        return False

    def _find_permit(self, source_code, abi):
        found_permit_in_abi = False
        for attr in abi:
            n = attr.get('name', '').lower()
            if n == 'permit':
                found_permit_in_abi = True
                break

        found_permit_func = self._find_permit_func(source_code)
        found_signature = self._find_signature(source_code)
        found_domain_sep = self._find_domain_separator(source_code)
        found_domain_sep_func = self._find_domain_separator_func(source_code)
        found_nonces = self._find_nonces(source_code)
        found_nonces_func = self._find_nonces_func(source_code)

        # is permit only requires that permit function is found
        is_permit = found_permit_func

        res = {
            "permit_in_abi": found_permit_in_abi,
            "permit_func": found_permit_func,
            "signature": found_signature,
            "nonces": found_nonces,
            "nonces_func": found_nonces_func,
            "domain_separator": found_domain_sep,
            "domain_separator_func": found_domain_sep_func,
            "is_permit": is_permit
        }
        return res

    def identify_permit(self, symbol, token_address):
        try:
            # -------------------- check abi ------------------------------
            # found_permit_in_abi = self._check_abi(token_address)

            # -------------------- check source code ------------------------------
            # get source code
            source_code, abi, constructor_argument, is_proxy, e = self._get_source_code(token_address)
            if e is not None:
                raise e
            # get implementation contract
            impl_contract, e = self._find_implement_contract(is_proxy, source_code, constructor_argument, token_address)
            if e is not None:
                raise e
            source_code_impl, abi_impl = '', ''
            if impl_contract != '':
                source_code_impl, abi_impl, _, _, e = self._get_source_code(impl_contract)
                if e is not None:
                    raise Exception('failed to get impl contract')

            # -------- check source code --------
            """ Condition 1: MUST have permit function that is deployed """
            if impl_contract == '':
                res = self._find_permit(source_code, abi)
            else:
                res = self._find_permit(source_code_impl, abi_impl)

            # logging
            res['symbol'] = symbol
            res['address'] = token_address
            res['impl_contract'] = impl_contract
            res['error'] = None
            # pp.pprint(res)
            self._logger.info(json.dumps(res))
            return res
        except (Exception,) as e:
            line = {"symbol": symbol, "address": token_address, "impl_contract": '',
                    "error": f'fail get source code {e}'}
            # print(line)
            self._logger.warning(json.dumps(line))
            return line

    def stop(self):
        self._logger.stop_log()


def test():
    p = PermitDetector('configs/test_config.json')
    # contract with proxy
    p.identify_permit('USDC', '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')
    p.identify_permit('SWISE', '0x48c3399719b582dd63eb5aadf12a40b4c3f52fa2')
    p.identify_permit('gOHM', '0x0ab87046fbb341d058f17cbc4c1133f25a20a52f')
    p.identify_permit('CULT', '0xf0f9d895aca5c8678f706fb8216fa22957685a13')
    p.identify_permit('AMPL', '0xd46ba6d942050d489dbd938a2c909a5d5039a161')
    p.identify_permit('sETH2', '0xfe2e637202056d30016725477c5da089ab0a043a')
    p.identify_permit('agEUR', '0x1a7e4e63778b4f12a199c062f3efdd288afcbce8')
    p.identify_permit('EUROC', '0x1abaea1f7c830bd89acc67ec4af516284b1bc33c')
    p.identify_permit('AUDIO', '0x18aaa7115705e8be94bffebde57af9bfc265b998')
    p.identify_permit('RARE', '0xba5bde662c17e2adff1075610382b9b691296350')
    p.identify_permit('aWETH', '0x030ba81f1c18d280636f32af80b9aad02cf0854e')
    p.identify_permit('VERSE', '0x7ae0d42f23c33338de15bfa89c7405c068d9dc0a')
    p.identify_permit('T', '0x5b985b4f827072febe33091b42729522b557bba1')
    p.identify_permit('aUSDC', '0xbcca60bb61934080951369a648fb03df4f96263c')
    p.identify_permit('MET', '0x1ffe8a8177d3c261600a8bd8080d424d64b7fbc2')
    p.identify_permit('OOKI', '0x0de05f6447ab4d22c8827449ee4ba2d5c288379b')
    p.identify_permit('pBTC35A', '0xa8b12cc90abf65191532a12bb5394a714a46d358')
    p.identify_permit('INST', '0x6f40d4a6237c257fff2db00fa0510deeecd303eb')
    p.identify_permit('JRT', '0x8a9c67fee641579deba04928c4bc45f66e26343a')
    p.identify_permit('UDT', '0x90de74265a416e1393a450752175aed98fe11517')
    p.identify_permit('BCT', '0x5c523d6abe17e98eaa58c2df62a6ec9162f3b9a1')
    p.identify_permit('aWBTC', '0x9ff58f4ffb29fa2266ab25e75e2a8b3503311656')
    p.identify_permit('BOB', '0xb0b195aefa3650a6908f15cdac7d92f8a5791b0b')
    p.identify_permit('aDAI', '0x028171bca77440897b824ca71d1c56cac55b68a3')
    p.identify_permit('aUSDT', '0xf8fd466f12e236f4c96f7cce6c79eadb819abf58')
    p.identify_permit('aLINK', '0xa06bc25b5805d5f8d82847d191cb4af5a3e873e0')
    p.identify_permit('aSUSD', '0x625ae63000f46200499120b906716420bd059240')
    p.identify_permit('OHM', '0x0ab87046fbb341d058f17cbc4c1133f25a20a52f')


if __name__ == '__main__':
    x = pd.read_csv('configs/token_list_0xapi_eth.csv')
    token_list = x[['symbol', 'address']].copy()

    # get the list of 1inch
    df_1inch = pd.read_csv('configs/1inch_permit_tokens_eth.csv')
    for i in range(len(df_1inch)):
        t = df_1inch.address.iloc[i].lower()
        if (token_list.address == t).any():
            continue
        token_list.loc[len(token_list)] = ['', t]

    n_tokens = len(token_list)

    p = PermitDetector('configs/test_config.json')

    for i in range(n_tokens):
        symbol, address = token_list.iloc[i]
        result = p.identify_permit(symbol, address)
        if result.get('is_permit', False):
            print(i, result['symbol'], result.get('is_permit', None), result['error'])
        time.sleep(0.3)

    time.sleep(5)
    p.stop()
