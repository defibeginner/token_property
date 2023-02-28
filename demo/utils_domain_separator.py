#!/usr/bin/env python

"""
util functions of finding domain separator

"""

import re
from web3 import Web3
from eip712_structs import make_domain
from eip712_structs import EIP712Struct, String, Uint, Address
from sklearn.model_selection import ParameterGrid

__author__ = "yun"
__copyright__ = ""
__credits__ = ['Robert', 'Phil']
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


# define a struct type
# reference: https://medium.com/treum_io/introducing-eip-712-structs-in-python-27eac7f38281
# we could create a domain object using this EIP712Domain class
# but make_domain() function created the same object
class EIP712Domain(EIP712Struct):
    name = String()
    version = String()
    chainId = Uint(256)
    verifyingContract = Address()


def find_right_bracket(s):
    """

    find_right_bracket("{d, {3, 4}, {5, {6, 7}}}, {1, 2}")
    (23, None)

    :param s:
    :return:
    """

    try:
        assert s[0] == '{', 'starting of str must be left bracket'
        pstack = []
        for i, c in enumerate(s):
            if c == '{':
                pstack.append(i)
            elif c == '}':
                if len(pstack) == 0:
                    raise IndexError(f"No matching closing brackets at {i}")
                elif len(pstack) > 1:
                    pstack.pop()
                elif len(pstack) == 1:
                    return i, None
        raise IndexError("No matching opening brackets at")
    except (Exception,) as e:
        return None, e


def find_right_paren(s):
    """

    find_right_paren("(d, (3, 4), (5, (6, 7))), (1, 2)")
    (23, None)

    :param s:
    :return:
    """
    try:
        assert s[0] == '(', 'starting of str must be left paren'
        pstack = []
        for i, c in enumerate(s):
            if c == '(':
                pstack.append(i)
            elif c == ')':
                if len(pstack) == 0:
                    raise IndexError(f"No matching closing paren at {i}")
                elif len(pstack) > 1:
                    pstack.pop()
                elif len(pstack) == 1:
                    return i, None
        raise IndexError("No matching opening paren at")
    except (Exception,) as e:
        return None, e


def is_paren_safe(s: str):
    """
    return True if the string is parenthesis safe
    i.e., all the left and right parenthesis match and makes it a valid string

    for example,
    is_paren_safe('keccak256(abi.encode(keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"), '
                  'chainId, address(this)));')
    True

    :param s:
    :return: bool
    """
    i = 0
    while i < len(s):
        c = s[i]
        if c == ')':
            return False
        if c != '(':
            i += 1
            continue
        j, e = find_right_paren(s[i:])
        if e is not None:
            return False
        s = s[i+j+1:]
        i = 0
    return True


def get_domain_separator(w3, token_address, abi):
    """
    try to call the domain separator function of the contract to get the domain separator
    the standard function name is DOMAIN_SEPARATOR, but may have different names:
        1. `DOMAIN_SEPARATOR`
        2. `EIP712_DOMAIN_SEPARATOR`
        3. `getDomainSeparator`
        4. `getDomainSeperator`
        5. `domainSeparator`
        6. `domainSeparatorV4`
        7. More function names to be found

    TODO: could use function selector to simplify. https://solidity-by-example.org/function-selector/

    :param w3:
    :param token_address: we always use the token's address (instead of the implementation address)
    :param abi: if the token contract used proxy,
        we need to create the contract using the token address and the implementation abi
    :return: domain_separator (bytes32), error
    """

    def _try1():
        try:
            _dom_sep_bytes = contract.functions.DOMAIN_SEPARATOR().call()
            return _dom_sep_bytes, None
        except (Exception,) as _e:
            return None, _e

    def _try2():
        try:
            _dom_sep_bytes = contract.functions.EIP712_DOMAIN_SEPARATOR().call()
            return _dom_sep_bytes, None
        except (Exception,) as _e:
            return None, _e

    def _try3():
        try:
            _dom_sep_bytes = contract.functions.getDomainSeperator().call()
            return _dom_sep_bytes, None
        except (Exception,) as _e:
            return None, _e

    def _try4():
        try:
            _dom_sep_bytes = contract.functions.getDomainSeparator().call()
            return _dom_sep_bytes, None
        except (Exception,) as _e:
            return None, _e

    def _try5():
        try:
            _dom_sep_bytes = contract.functions.domainSeparator().call()
            return _dom_sep_bytes, None
        except (Exception,) as _e:
            return None, _e

    def _try6():
        try:
            _dom_sep_bytes = contract.functions.domainSeparatorV4().call()
            return _dom_sep_bytes, None
        except (Exception,) as _e:
            return None, _e

    try:
        known_funcs = [_try1, _try2, _try3, _try4, _try5, _try6]

        # if the token contract used proxy
        # we need to create the contract using the token address and the implementation abi
        contract = w3.eth.contract(address=Web3.toChecksumAddress(token_address), abi=abi)
        for func in known_funcs:
            dom_sep_bytes, e = func()
            if e is not None or dom_sep_bytes == bytearray(32):
                # ROUTE (0x16eccfdbb4ee1a85a33f3a9b21175cd7ae753db4) 's getDomainSeparator() returns bytearray(32)
                # bytearray(32) is all 0 string is not valid
                continue
            # dom_sep_str = Web3.toHex(dom_sep_bytes)
            return dom_sep_bytes, None
        raise Exception('no domain_separator function')
    except (Exception,) as e:
        return None, e


def get_domain_by_guess(w3, token_address, abi, dom_sep_bytes):
    """
    this follows Phil's guessDomain method
    just try all the possible combinations of the domain fields
    {name, version, chainId, address, salt}
        1. `name`: just use the token name.
            (this might not be correct, so this method cannot guarantee we always find the domain)
        2. `version`: {0, 0.0, 0.0.0, 1, 1.0, 1.0.0, 2, 2.0, 2.0.0}
        3. `chainId`: just 1 for Ethereum. and just use the corresponding chainId for other chains.
        4. `verifyingContract`: just the token address.
            If it is a proxy, still use the address instead of the implementation address.
        5. `salt`: TODO: I did not figure out a good way to guess the salt, so salt is not included yet
            But fortunately, almost all the permit tokens do not have salt.

    then use make_domain function to get the domain separator
    compare it with the domain separator that is obtained from the contract domain separator function
    if the two match, it means we find the right domain fields

    :param w3:
    :param token_address: we always use the token's address (instead of the implementation address)
    :param abi: if the token contract used proxy,
        we need to create the contract using the token address and the implementation abi

    :param dom_sep_bytes:
    :return: domain fields, which is a dict
        {'name': known_names,
         'version': known_versions,
         'chainId': known_chain_ids,
         'verifyingContract': known_contracts}
    """
    try:
        # ---------- get token name ----------
        # if the token contract used proxy
        # we need to create the contract using the token address and the implementation abi
        contract = w3.eth.contract(address=Web3.toChecksumAddress(token_address), abi=abi)
        # symbol = contract.functions.symbol().call()
        # TODO: OverflowError when it is used for MKR token
        name = contract.functions.name().call()
        # decimal = contract.functions.decimals().call()  # token decimal

        # ---------- parameter grid ----------
        # note that we need to add a None to the parameter, as the domain fields are all optional
        known_names = [None, name]
        known_contracts = [None, token_address]
        known_versions = [None, '0', '0.0', '0.0.0',
                          '1', '1.0', '1.0.0',
                          '2', '2.0', '2.0.0']  # https://chainlist.org/
        known_chain_ids = [None, 1]

        # ---------- create the domain separator and compare it with the input domain separator ----------
        param_grid = {'name': known_names, 'version': known_versions,
                      'chainId': known_chain_ids, 'verifyingContract': known_contracts}
        for param in ParameterGrid(param_grid):
            param_trim = {k: v for k, v in param.items() if v is not None}
            if param_trim:
                # Make a Domain Separator
                domain = make_domain(**param_trim)
                guessed_hash = domain.hash_struct()
                if guessed_hash == dom_sep_bytes:
                    return param_trim, None
        return None, None
    except (Exception,) as e:
        return None, e


def find_domain_separator_parameters(code_line):
    """
    parse the parameters of domain separator in the source code

    for example,

    code_line = "    DOMAIN_SEPARATOR = keccak256("\
                "        abi.encode("\
                "            DOMAIN_TYPE_HASH,"\
                "            DOMAIN_NAME_HASH,"\
                "            DOMAIN_VERSION_HASH,"\
                "            _getChainID(),"\
                "            address(this),"\
                "            DOMAIN_SALT"\
                "        )"\
                "    );"
    find_domain_parameter_parameters(code_line)
    (True,
     ['DOMAIN_TYPE_HASH', 'DOMAIN_NAME_HASH', 'DOMAIN_VERSION_HASH',
      '_getChainID()', 'address(this)', 'DOMAIN_SALT']
    )


    :param code_line:
    :return:
    """
    left = code_line.find('abi.encode')
    if left == 0:
        return False, {}
    line = code_line[left+10:]
    right, e = find_right_paren(line)
    if e is not None:
        return False, {}
    line = line[1:right]
    line = line.replace('\n', '')
    line = line.replace('\r', '')
    line = line.replace('\\n', '')
    # line = line.replace(' ', '')  # this may have problems
    line = line.replace('\\u0027', '')
    splits = line.split(',')
    i = 0
    while i < len(splits):
        if is_paren_safe(splits[i]):
            i += 1
            continue
        merge = ''
        for j in range(i, len(splits)):
            merge += splits[j]
            if is_paren_safe(merge):
                splits = splits[:i] + [merge] + splits[j+1:]
                break
            else:
                j += 1
        else:
            return False, {}
    splits = [split.strip() for split in splits]
    return True, splits


def find_hash_string(source_code1, key):
    """
    s = 'bytes32 private constant domain_name_hash = keccak256("graph token");'
    key = 'domain_name_hash'
    find_hash_string(s, key)

    (True, 'graph token')

    :param source_code1:
    :param key:
    :return:
    """
    known_names = [f'{key}=', f'{key} =']
    for name in known_names:
        for m in re.finditer(name, source_code1):
            left = m.start()
            right = source_code1[left:].find(';')
            if right == -1:
                continue
            s = source_code1[left+len(name):left+right]
            s = s.replace('\\', '')
            i = s.find('keccak256')
            if i == -1:
                continue
            s = s[i:]
            j = s.find('"')
            if j == -1:
                continue
            k = s[j+1:].find('"')
            if k == -1:
                continue
            s = s[j+1:j+1+k]
            if len(s) > 0:
                return True, s
            return True, s
    return False, None


def _get_salt(line, key):
    """

    line = 'bytes32 private constant DOMAIN_SALT = 0x51f3d585afe6dfeb2af01bba0889a36c1db03beec88c6a4d0c53817069026afa;'
    key = 'DOMAIN_SALT'
    _get_salt(line, key)

    (True, '0x51f3d585afe6dfeb2af01bba0889a36c1db03beec88c6a4d0c53817069026afa')

    :param line:
    :param key:
    :return:
    """
    known_names = [f'{key}=', f'{key} =']
    for name in known_names:
        for m in re.finditer(name, line):
            left = m.start()
            right = line[left:].find(';')
            if right == -1:
                continue
            s = line[left+len(name):left+right]
            i = s.find('0x')
            if i == -1:
                continue
            s = s[i:]
            if len(s) > 0:
                return True, s
            return True, s
    return False, None


def _get_name(s):
    """
    s = 'keccak256(bytes(\\"AliERC20v2\\"))'
    _get_name(s)

    (True, 'AliERC20v2')

    :param s:
    :return:
    """
    s = s.replace('\\r', '')
    s = s.replace('\\n', '')
    s = s.replace('\\', '')
    i = s.find('keccak256')
    if i == -1:
        return False, s
    s = s[i:]
    j = s.find('"')
    if j == -1:
        return False, s
    k = s[j + 1:].find('"')
    if k == -1:
        return False, s
    s = s[j + 1:j + 1 + k]
    if len(s) > 0:
        return True, s
    return False, s


def _get_version(s):
    """
    _get_version('keccak256(bytes(1))')
    (True, '1')

    _get_version('keccak256("0")')
    (True, '0')

    :param s:
    :return:
    """
    s = s.replace('\\r', '')
    s = s.replace('\\n', '')
    s = s.replace('\\', '')
    s = s.replace('keccak256', '')
    s = s.replace('bytes', '')
    s = s.replace('(', '')
    s = s.replace(')', '')
    s = s.replace('"', '')
    s = s.replace(' ', '')
    if len(s) > 0 and s.isnumeric():
        return True, s
    return False, s


def find_domain_separator_in_code(code_line, w3, token_address, source_code, abi):
    try:
        # get domain params
        contract = w3.eth.contract(address=Web3.toChecksumAddress(token_address), abi=abi)
        # symbol = contract.functions.symbol().call()
        # TODO: OverflowError when it is used for MKR token
        token_name = contract.functions.name().call()
        # decimal = contract.functions.decimals().call()  # token decimal

        # ---------- get parameters from the code line ----------
        found, splits = find_domain_separator_parameters(code_line)
        if not found:
            raise Exception('domain_separator invalid code')
        assert len(splits) >= 4, 'domain_separator invalid code'
        """
        the length of splits shall 6 (following the standard)
        https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
        splits[0]: domain_hash
        splits[1]: name
        splits[2]: version  -- optional
        splits[3]: chain id
        splits[4]: address
        splits[5]: salt  -- optional
        """
        ret = {}
        # name
        split = splits[1]  # TODO: this is hardcoded, however, the 2nd parameter may not be name. An example is FOLD
        found, hardcoded_token_name = find_hash_string(source_code, split)
        if found:
            ret['name'] = hardcoded_token_name
        else:
            found, hardcoded_token_name = _get_name(split)
            if found:
                ret['name'] = hardcoded_token_name
            else:
                ret['name'] = token_name
        # chainId
        # one of the split must be getChainId(), chainId(), or similar
        for split in splits[1:]:
            if 'chainid' in split.lower():
                ret['chainId'] = 1  # TODO: hardcoded
        # address
        # one of the split must be address(this)
        for split in splits[1:]:
            if 'address' in split.lower():
                ret['verifyingContract'] = token_address  # TODO: hardcoded
        # salt
        # salt is the last parameter
        # the following logic does not guarantee to find salt, so report error if failed to find slat
        salt_found = False
        if 'address' not in splits[-1].lower():
            # the last parameter is not address, it will be salt
            salt_found = True
            found, hardcoded_salt = _get_salt(source_code, splits[-1])
            if found:
                ret['salt'] = hardcoded_salt
            else:
                raise Exception('Cannot found salt in source code')
        # version
        # if there are 6 parameters --> there is version
        # if there are 5 parameters, and the last one is not address (it means there is no slat)
        # the following logic does not guarantee to find version, so report error if failed to find version
        if len(splits) == 6 or (len(splits) == 5 and not salt_found):
            split = splits[2]
            found, hardcoded_version = find_hash_string(source_code, split)
            if found:
                ret['version'] = hardcoded_version
            else:
                found, ver = _get_version(split)
                if found:
                    ret['version'] = ver
                else:
                    raise Exception('Cannot found version in source code')

        if len(ret) > 0:
            return ret, None
        else:
            raise Exception('domain_separator invalid code')
    except (Exception,) as e:
        return None, e


def rem_comments(line):
    """
    remove the comments in the code lines
    comments are strings between "//" and "\n" (or "\\n")

    :param line:
    :return:
    """
    i = line.find('//')
    while i != -1:
        j1 = line[i:].find('\\n')
        j2 = line[i:].find('\n')
        j = max(j1, j2)
        if j == -1:
            line = line[:i]
        else:
            line = line[:i] + line[i+j:]
        i = line.find('//')
    return line


def get_domain_in_source_code(w3, token_address, source_code, abi):
    """
    find the domain in source code

    :param w3:
    :param token_address:
    :param source_code:
    :param abi:
    :return: domain_param, domain_separator, error
    """
    try:
        # get domain params
        source_code_lower = source_code.lower()
        names = ['domain_separator', 'eip712_domain_separator', 'getdomainseperator',
                 'domainseparator', 'domainseparatorv4']
        known_names = []
        for name in names:
            for equal_sign in [' =', '=']:
                known_names.append(name + equal_sign)

        for name in known_names:
            for m in re.finditer(name, source_code_lower):
                left = m.start()
                right = source_code_lower[left:].find(';')
                if right == -1:
                    continue
                code_line = source_code[left:left + right]  # here MUST use the original source code
                if 'abi.encode' not in code_line:
                    continue
                # remove comments
                code_line = rem_comments(code_line)
                # parse the domain parameters
                domain_param, e = find_domain_separator_in_code(code_line, w3, token_address, source_code, abi)
                if e is not None:
                    raise e
                # Make a Domain Separator
                domain = make_domain(**domain_param)
                guessed_hash = domain.hash_struct()
                return domain_param, guessed_hash, None
        raise Exception('domain not found')

    except (Exception,) as e:
        return None, None, e
