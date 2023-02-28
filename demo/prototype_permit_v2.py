#!/usr/bin/env python

"""
prototype permit
version 2

domain separator is added

"""

import re
import pprint
import json
import requests
from web3 import Web3
from utils_domain_separator import get_domain_separator, get_domain_by_guess, get_domain_in_source_code

__author__ = "yun"
__copyright__ = ""
__credits__ = ['Robert', 'Phil']
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
    :param source_code:
    :param abi:
    :return:
    """
    try:
        # get the domain separator by calling the contract method
        dom_sep_bytes, e = get_domain_separator(w3, token_address, abi)

        if e is not None or dom_sep_bytes == b'' or dom_sep_bytes == bytearray(32):
            # find domain from source code
            domain_param, dom_sep_bytes, e = get_domain_in_source_code(w3, token_address, source_code, abi)
            if e is not None:
                raise e
        else:
            # find domain by guessing
            domain_param, e = get_domain_by_guess(w3, token_address, abi, dom_sep_bytes)
            if e is not None:
                raise e
            if domain_param is None:
                # if we failed by guessing, then try to find domain from source code
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

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(self.RPC_URL))

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
            # constructor_argument = data['result'][0]['ConstructorArguments'].lower()
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
        known_func_names = ['domain_separator', 'eip712_domain_separator', 'getdomainseparator',
                            'getdomainseperator', 'domainseparator', '_domainseparatorv4']
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
        # final signature starts with uint16(0x1901)
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

            ret = {
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
            return ret, None
        except (Exception,) as e:
            return None, e

    def identify_permit(self, token_address):
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
                ret, e = self._find_permit(token_address, source_code, abi)
            else:
                # STILL use token_address instead of impl_address
                ret, e = self._find_permit(token_address, source_code_impl, abi_impl)
            if e is not None:
                raise e

            # res['symbol'] = symbol
            ret['address'] = token_address
            ret['impl_contract'] = impl_contract
            ret['error'] = None
            return ret
        except (Exception,) as e:
            ret = {"address": token_address, "impl_contract": '',
                   "error": str(e)}
            return ret


if __name__ == '__main__':
    p = PermitDetector()

    res = p.identify_permit('0x5f98805a4e8be255a32880fdec7f6728c6568ba0')  # LUSD
    pp.pprint(res)
    res = p.identify_permit('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')  # USDC
    pp.pprint(res)
    res = p.identify_permit('0x1f9840a85d5af5bf1d1762f925bdaddc4201f984')  # UNI
    pp.pprint(res)
    res = p.identify_permit('0x853d955acef822db058eb8505911ed77f175b99e')  # FRAX
    pp.pprint(res)
    res = p.identify_permit('0xc944E90C64B2c07662A292be6244BDf05Cda44a7')  # GRT
    pp.pprint(res)
    res = p.identify_permit('0x6b0b3a982b4634ac68dd83a4dbf02311ce324181')  # ALI
    pp.pprint(res)
    res = p.identify_permit('0xd084944d3c05cd115c09d072b9f44ba3e0e45921')  # FOLD
    pp.pprint(res)
    res = p.identify_permit('0xe80c0cd204d654cebe8dd64a4857cab6be8345a3')  # JPEG
    pp.pprint(res)
    res = p.identify_permit('0x6399c842dd2be3de30bf99bc7d1bbf6fa3650e70')  # PREMIA
    pp.pprint(res)
    res = p.identify_permit('0x0d438f3b5175bebc262bf23753c1e53d03432bde')  # wNXM
    pp.pprint(res)
    res = p.identify_permit('0xa117000000f279d81a1d3cc75430faa017fa5a2e')  # ANT
    pp.pprint(res)
    res = p.identify_permit('0x16eccfdbb4ee1a85a33f3a9b21175cd7ae753db4')  # ROUTE
    pp.pprint(res)
    res = p.identify_permit('0xeef9f339514298c6a857efcfc1a762af84438dee')  # HEZ
    pp.pprint(res)
