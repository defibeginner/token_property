#!/usr/bin/env python

"""
main script of permit
"""

import re
import pprint
import json
import requests
from web3 import Web3

__author__ = "yun"
__copyright__ = ""
__credits__ = ["Robert Paluba", "Phil Liao"]
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


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

    I used a very simple and stupid method, that is
    find if there is a left-bracket "{" after the function name.
    :(

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


def find_implementation_slot(source_code, known_name):
    """
    this function tries to parse the implementation_slot or implementation_storage
    from the source code

    :param source_code:
    :param known_name:
    :return:
    """
    for m in re.finditer(known_name, source_code):
        left = m.start()
        if left != -1:
            j = source_code[left:].find(';')
            k = source_code[left:left+j].find('0x')  # because impl_slot starts with '0x'
            if j != -1 and k != -1:
                implementation_slot = source_code[left + k:left + j]
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
    # i = source_code.find(f'function {function_name}(')
    for m in re.finditer('function permit', source_code):
        left = m.start()
        right = source_code[left:].find(';')
        if right == -1:
            continue
        left_bracket = source_code[left:left+right].find('{')
        # right_bracket = source_code[i:i+j].find('}')
        if left_bracket == -1:
            continue
        # locate where the permit function is implemented
        func_declare = source_code[left:left+right]
        if 'bool ' in func_declare:
            # if there is a boolean parameter, it is DAI-type
            return 'DAI'
        if find_function_in_source_code(source_code, 'nonces') and \
                find_function_in_source_code(source_code, 'domain_separator'):
            # if there are both nonces function and domain_separator function
            # it is a standard permit token
            return 'UniV2_Standard'
        else:
            # otherwise, it is non-standard
            return 'UniV2_NonStandard'
    return 'NotPermit'


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
            source_code = data['result'][0]['SourceCode'].lower()
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
            # ---------- step 2: return the implementation that is from ABI ----------
            # a simply but dirty solution is used:
            # just return the data['result'][0]['implementation']
            return impl, None
            # ---------- step 3: decode constructor argument ----------
            # shall be decoded from constructor arguments
            # using Rob's demo, demo_decode_constructor_argument.py
            # because in the research, we got the implementation contract of all the tokens
            # either in step 1 or step 2, so I have not yet added this step

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

    def _find_domain_separator(self, token_address, abi, is_permit):
        try:
            if not is_permit:
                return '', None
            contract = self.w3.eth.contract(address=Web3.toChecksumAddress(token_address), abi=abi)
            if 'DOMAIN_SEPARATOR' in abi:
                dom_sep_bytes32 = contract.functions.DOMAIN_SEPARATOR().call()
                dom_sep_str = Web3.toHex(dom_sep_bytes32)
            else:
                dom_sep_str = '0x'
            return dom_sep_str, None
        except (Exception,) as e:
            return None, e

    def _find_permit(self, token_address, source_code, abi):
        try:
            found_permit_in_abi = find_key_in_abi(abi, 'permit')
            found_permit_func = self._find_permit_func(source_code)
            found_signature = self._find_signature(source_code)
            found_domain_sep = self._find_eip712domain(source_code)
            found_domain_sep_func = self._find_domain_separator_func(source_code)
            found_nonces = self._find_nonces(source_code)
            found_nonces_func = self._find_nonces_func(source_code)

            """ is_permit only requires that permit function is implemented """
            is_permit = found_permit_func

            dom_sep, e = self._find_domain_separator(token_address, abi, is_permit)
            if e is not None:
                raise e

            permit_type = find_permit_type(source_code)

            res = {
                "permit_in_abi": found_permit_in_abi,
                "permit_func": found_permit_func,
                "signature": found_signature,
                "nonces": found_nonces,
                "nonces_func": found_nonces_func,
                "found_domain_separator": found_domain_sep,
                "found_domain_separator_func": found_domain_sep_func,
                "is_permit": is_permit,
                "domain_separator": dom_sep,
                'permit_type': permit_type,
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
                res, e = self._find_permit(impl_contract, source_code_impl, abi_impl)
            if e is not None:
                raise e

            # logging
            res['symbol'] = symbol
            res['address'] = token_address
            res['impl_contract'] = impl_contract
            res['error'] = None
            return res
        except (Exception,) as e:
            res = {"symbol": symbol, "address": token_address, "impl_contract": '',
                   "error": str(e)}
            return res


if __name__ == '__main__':
    pp = pprint.PrettyPrinter()

    p = PermitDetector()

    result = p.identify_permit('DAI', '0x6B175474E89094C44Da98b954EedeAC495271d0F')
    pp.pprint(result)

    result = p.identify_permit('USDC', '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')
    pp.pprint(result)

    result = p.identify_permit('SYN', '0x0f2d719407fdbeff09d87557abb7232601fd9f29')
    pp.pprint(result)
