#!/usr/bin/env python

"""
main script of permit

v3: domain is added

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
from eip712_structs import make_domain
from eip712_structs import EIP712Struct, String, Uint, Address

from sklearn.model_selection import ParameterGrid
from utils import get_domain_separator, get_domain_by_guess, get_domain_in_source_code

__author__ = "yun"
__copyright__ = ""
__credits__ = ""
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


pp = pprint.PrettyPrinter()


def find_key_in_abi(abi, key):
    abi_json = json.loads(abi)
    key_lower = key.lower()
    for attr in abi_json:
        if attr.get('name', '').lower() == key_lower:
            return True
    return False


def find_function_in_source_code(source_code, function_name):
    """
    function must be implemented instead of being imported from interface

    :param source_code:
    :param function_name:
    :return:
    """
    source_code_lower = source_code.lower()
    # i = source_code_lower.find(f'function {function_name}(')
    for m in re.finditer(f'function {function_name}', source_code_lower):
        left = m.start()
        right = source_code_lower[left:].find(';')
        if right == -1:
            continue
        left_bracket = source_code_lower[left:left+right].find('{')
        # right_bracket = source_code_lower[i:i+j].find('}')
        #
        if left_bracket != -1:
            return True
    return False


def find_implementation_slot(source_code, known_name):
    source_code_lower = source_code.lower()
    for m in re.finditer(known_name, source_code_lower):
        left = m.start()
        if left != -1:
            j = source_code_lower[left:].find(';')
            k = source_code_lower[left:left+j].find('0x')
            if j != -1 and k != -1:
                implementation_slot = source_code_lower[left + k:left + j]
                return implementation_slot
    return ''


def find_permit_type(source_code):
    """
    function must be implemented instead of being imported from interface

    1. DAI ERC20 Permit
        function permit(address holder, address spender, uint256 nonce, uint256 expiry,
                        bool allowed, uint8 v, bytes32 r, bytes32 s) external
    2. Univswap ERC20 Permit (standard EIP2612)
        https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2ERC20.sol
        function permit(address owner, address spender, uint256 value, uint256 deadline,
                        uint8 v, bytes32 r, bytes32 s) external
        And requires to have nonces() and domain_separator() function
    3. Non-stardard Univswap ERC20 Permit
        function permit(address owner, address spender, uint256 value, uint256 deadline,
                        uint8 v, bytes32 r, bytes32 s) external
        But does not have nonces() or domain_separator() function

    :param source_code:
    :return:
    """
    source_code_lower = source_code.lower()
    # i = source_code.find(f'function {function_name}(')
    for m in re.finditer('function permit', source_code_lower):
        left = m.start()
        right = source_code_lower[left:].find(';')
        if right == -1:
            continue
        left_bracket = source_code_lower[left:left+right].find('{')
        # right_bracket = source_code_lower[i:i+j].find('}')
        if left_bracket == -1:
            continue
        # is a permit token
        func_declare = source_code_lower[left:left+right]
        if 'bool ' in func_declare:
            return 'DAI'
        if find_function_in_source_code(source_code_lower, 'nonces') and \
                find_function_in_source_code(source_code_lower, 'domain_separator'):
            return 'UniV2_Standard'
        else:
            return 'UniV2_NonStandard'
    return 'NotPermit'


def get_domain(w3, token_address, source_code, abi):
    """
    reference for signing data
    https://docs.metamask.io/guide/signing-data.html#signtypeddata-v4

    :param w3:
    :param token_address:
    :param abi:
    :return:
    """
    try:
        dom_sep_bytes, e = get_domain_separator(w3, token_address, abi)

        if e is not None or dom_sep_bytes == b'' or dom_sep_bytes == bytearray(32):
            # find domain from source code
            domain_param, dom_sep_bytes, e = get_domain_in_source_code(w3, token_address, source_code, abi)
            if e is not None:
                raise e
        else:
            domain_param, e = get_domain_by_guess(w3, token_address, abi, dom_sep_bytes)
            if e is not None:
                raise e
            if domain_param is None:
                # try to find domain from source code
                guessed_domain_param, guessed_dom_sep_bytes, e = \
                    get_domain_in_source_code(w3, token_address, source_code, abi)
                if guessed_dom_sep_bytes == dom_sep_bytes:
                    domain_param = guessed_domain_param

        dom_sep_str = Web3.toHex(dom_sep_bytes)
        return dom_sep_str, domain_param, None

    except (Exception,) as e:
        return None, None, e


class PermitDetector(object):

    API_KEY = 'PR8IBWAK7QQ37TCCBC1JIIJ9I8JFSP15M9'
    ETH_API_URL = 'https://api.etherscan.io/api'

    RPC_URL = "https://eth-mainnet.alchemyapi.io/v2/sBFFXcfLNdXl-Ym71hIwfpvhzAtdLE2e"

    REGEX = '(?:5b)?(?:60([a-z0-9]{2})|61([a-z0-9_]{4})|62([a-z0-9_]{6}))80(?:60([a-z0-9]{2})|61([a-z0-9_]{4})|62([a-z0-9_]{6}))6000396000f3fe'

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

    def _get_source_code(self, token_address):
        try:
            params = {'module': 'contract',
                      'action': 'getsourcecode',
                      'address': token_address,
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
            source_code = data['result'][0]['SourceCode']
            abi = data['result'][0]['ABI']
            # abi_json = json.loads(abi)
            constructor_argument = data['result'][0]['ConstructorArguments'].lower()
            impl = data['result'][0]['Implementation'].lower()

            is_proxy = find_key_in_abi(abi, 'implementation')

            return source_code, abi, impl, is_proxy, None
        except (Exception,) as e:
            return None, None, None, None, e

    @staticmethod
    def _find_impl_slot(source_code):
        known_names = ["implementation_slot =", "implementation_slot=", "impl_slot=", "impl_slot =" 
                       "implementation_storage ="]
        for name in known_names:
            impl_slot = find_implementation_slot(source_code, name)
            if impl_slot != '':
                return impl_slot
        return ''

    def _find_implement_contract(self, is_proxy, source_code, impl, token_address):
        try:
            if not is_proxy:
                return '', None
            # ---------- step 1: search "implementation slot" from source code ----------
            # find implementation slot
            implementation_slot = self._find_impl_slot(source_code)
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
            """ shall be decoded from constructor arguments
            using Rob's demo, demo_decode_constructor_argument.py
            for now, a simply but dirty solution is used:
            just return the data['result'][0]['implementation']
            """
            return impl, None
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
    def _find_eip712domain(source_code):
        known_names = ["eip712domain", "domain_separator"]
        for name in known_names:
            if name in source_code:
                return True
        return False

    def _find_domain(self, token_address, abi, source_code, is_permit):
        try:
            if not is_permit:
                return None, None, None

            dom_sep, domain, e = get_domain(self.w3, token_address, source_code, abi)
            if e is not None:
                raise e

            return dom_sep, domain, None

        except (Exception,) as e:
            return None, None, e

    def _find_permit(self, token_address, source_code, abi):
        try:
            found_permit_in_abi = find_key_in_abi(abi, 'permit')
            found_permit_func = self._find_permit_func(source_code)
            found_signature = self._find_signature(source_code)
            found_domain_sep = self._find_eip712domain(source_code)
            found_domain_sep_func = self._find_domain_separator_func(source_code)
            found_nonces = self._find_nonces(source_code)
            found_nonces_func = self._find_nonces_func(source_code)

            # is permit only requires that permit function is found
            is_permit = found_permit_func

            permit_type = find_permit_type(source_code)

            dom_sep, domain, e = self._find_domain(token_address, abi, source_code, is_permit)
            # if e is not None:
            #     raise e

            res = {
                "permit_in_abi": found_permit_in_abi,
                "permit_func": found_permit_func,
                "signature": found_signature,
                "nonces": found_nonces,
                "nonces_func": found_nonces_func,
                "found_domain_separator": found_domain_sep,
                "found_domain_separator_func": found_domain_sep_func,
                "is_permit": is_permit,
                'permit_type': permit_type,
                "domain_separator": dom_sep,
                'domain': domain,
            }
            return res, None
        except (Exception,) as e:
            return None, e

    def identify_permit(self, symbol, token_address):
        try:
            # -------------------- check abi ------------------------------
            # found_permit_in_abi = self._check_abi(token_address)

            # -------------------- check source code ------------------------------
            # get source code
            source_code, abi, impl, is_proxy, e = self._get_source_code(token_address)
            if e is not None:
                raise e
            # get implementation contract
            impl_contract, e = self._find_implement_contract(is_proxy, source_code, impl, token_address)
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
                res, e = self._find_permit(token_address, source_code, abi)
            else:
                # STILL use token_address instead of impl_address
                res, e = self._find_permit(token_address, source_code_impl, abi_impl)
            if e is not None:
                raise e

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
                    "error": str(e)}
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
    p.identify_permit('AAVE', '0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9')
    p.identify_permit('RARE', '0xba5bde662c17e2adff1075610382b9b691296350')

    p.identify_permit('YAM', '0x0aacfbec6a24756c20d41914f2caba817c0d8521')
    p.identify_permit('OOKI', '0x0de05f6447ab4d22c8827449ee4ba2d5c288379b')
    p.identify_permit('INST', '0x6f40d4a6237c257fff2db00fa0510deeecd303eb')

    p.identify_permit('LUSD', '0x5f98805a4e8be255a32880fdec7f6728c6568ba0')

    res = p.identify_permit('FRAX', '0x853d955acef822db058eb8505911ed77f175b99e')
    res = p.identify_permit('cbETH', '0xbe9895146f7af43049ca1c1ae358b0541ea49704')
    res = p.identify_permit('AAVE', '0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9')
    pp.pprint(res)

    res = p.identify_permit('USDC', '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')
    pp.pprint(res)
    res = p.identify_permit('UNI', '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984')
    pp.pprint(res)
    res = p.identify_permit('FRAX', '0x853d955acef822db058eb8505911ed77f175b99e')
    pp.pprint(res)
    res = p.identify_permit('GRT', '0xc944E90C64B2c07662A292be6244BDf05Cda44a7')
    pp.pprint(res)
    res = p.identify_permit('ALI', '0x6b0b3a982b4634ac68dd83a4dbf02311ce324181')
    pp.pprint(res)
    res = p.identify_permit('FOLD', '0xd084944d3c05cd115c09d072b9f44ba3e0e45921')
    pp.pprint(res)
    res = p.identify_permit('JPEG', '0xe80c0cd204d654cebe8dd64a4857cab6be8345a3')
    pp.pprint(res)
    res = p.identify_permit('PREMIA', '0x6399c842dd2be3de30bf99bc7d1bbf6fa3650e70')
    pp.pprint(res)
    res = p.identify_permit('wNXM', '0x0d438f3b5175bebc262bf23753c1e53d03432bde')
    pp.pprint(res)
    res = p.identify_permit('ANT', '0xa117000000f279d81a1d3cc75430faa017fa5a2e')
    pp.pprint(res)
    res = p.identify_permit('ROUTE', '0x16eccfdbb4ee1a85a33f3a9b21175cd7ae753db4')
    pp.pprint(res)
    res = p.identify_permit('HEZ', '0xeef9f339514298c6a857efcfc1a762af84438dee')
    pp.pprint(res)

    p.stop()


if __name__ == '__main__':
    # -------------------- option 1 ----------------------------------------
    x = pd.read_csv('configs/token_registry_202302171614.csv')
    df = x[['symbol', 'address']].copy()
    df['symbol'] = [str(x.symbol.iloc[i]) for i in range(len(x))]

    x = pd.read_csv('configs/token_list_0xapi_eth.csv')
    for i in range(len(x)):
        t = x.address.iloc[i].lower()
        sym = x.symbol.iloc[i]
        if (df.address == t).any():
            continue
        df.loc[len(df)] = [sym, t]

    # get the list of 1inch
    df_1inch = pd.read_csv('configs/1inch_permit_tokens_eth.csv')
    for i in range(len(df_1inch)):
        t = df_1inch.address.iloc[i].lower()
        if (df.address == t).any():
            continue
        df.loc[len(df)] = ['', t]

    n_tokens = len(df)

    # -------------------- option 2 ----------------------------------------
    # filename = 'results/permit/permit_9_crosscheck.csv'
    # df = pd.read_csv(filename)
    # n_tokens = len(df)

    # --------------------------------------------------------------------------------

    p = PermitDetector('configs/test_config.json')

    for i in range(n_tokens):
        # if df.iloc[i].is_permit_from_our_result is True or df.iloc[i].is_permit_from_1inch is True:
        if True:

            # symbol, address = token_list.iloc[i]
            symbol = df.iloc[i].symbol
            address = df.iloc[i].address

            result = p.identify_permit(symbol, address)

            if result.get('is_permit', False):
                print(f'{i}/{n_tokens}',
                      result['symbol'],
                      result.get('is_permit', -1),
                      result.get('domain_separator', -1),
                      result.get('permit_type', -1),
                      result.get('domain', -1),
                      result['error'])
            time.sleep(0.1)

    time.sleep(5)
    p.stop()
