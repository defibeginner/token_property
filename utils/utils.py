#!/usr/bin/env python

"""
util functions of finding domain separator

"""

__author__ = "yun"
__copyright__ = ""
__credits__ = ['Robert', 'Phil']
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


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
