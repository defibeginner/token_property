from web3 import Web3
from web3_input_decoder import decode_constructor
import re

REGEX = '(?:5b)?(?:60([a-z0-9]{2})|61([a-z0-9_]{4})|62([a-z0-9_]{6}))80(?:60([a-z0-9]{2})|61([a-z0-9_]{4})|62([a-z0-9_]{6}))6000396000f3fe'

BYTECODE = ''  # Bytecode with 0x removed at start
ABI = ''  # Contract abi


def main():
    offsets = re.findall(REGEX, BYTECODE)
    matches = [x for x in offsets if x]
    if len(matches) != 2:
        print('Something wrong')
    calldata_start = sum([Web3.toInt(hexstr=x) for x in matches]) * 2
    decoded = decode_constructor(ABI, BYTECODE[calldata_start:])


if __name__ == "__main__":
    main()
