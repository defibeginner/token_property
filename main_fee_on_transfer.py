import asyncio
import json

import aiohttp
from web3 import Web3

from web3.eth import AsyncEth

import pprint

pp = pprint.PrettyPrinter()

RPC_URL = 'http://localhost:8545'
w3 = Web3(Web3.AsyncHTTPProvider(RPC_URL), modules={'eth': (AsyncEth,)}, middlewares=[])


def load_json(path):
    with open(path) as f:
        return json.load(f)


ERC20 = w3.eth.contract(address=None, abi=load_json('configs/abi_erc20.json'))


async def call_many(session, txs, block_number):
    params = [[{"transactions": txs}], {"blockNumber": Web3.toHex(block_number), "transactionIndex": 0}]
    request = {"jsonrpc": "2.0", "method": "eth_callMany", "params": params, "id": 1}
    async with session.post("http://localhost:8545", json=request,
                            headers={"Content-Type": "application/json"}) as resp:
        response = await resp.json()
    return response


def prepare_balance_of(token, address, block_gas):
    calldata = ERC20.encodeABI(fn_name='balanceOf', args=[address])
    tx = {
        'data': calldata,
        'gas': Web3.toHex(0),
        'maxPriorityFeePerGas': '0x0',
        'maxFeePerGas': Web3.toHex(block_gas),
        'to': token,
        'value': '0x0'
    }
    return tx


def prepare_transfer(token, from_, to, amount, block_gas):
    calldata = ERC20.encodeABI(fn_name='transfer', args=[to, amount])
    tx = {
        'data': calldata,
        'gas': Web3.toHex(300000),
        'maxPriorityFeePerGas': '0x0',
        'maxFeePerGas': Web3.toHex(block_gas),
        'from': from_,
        'to': token
    }
    return tx


async def sim_transfer(session, block_number, token, from_, to, amount):
    block = await w3.eth.get_block(block_number)
    base_fee = block.baseFeePerGas
    get_balance = prepare_balance_of(token, to, base_fee)
    transfer = prepare_transfer(token, from_, to, amount, base_fee)
    callmany = await call_many(session, [get_balance, transfer, get_balance], block_number)
    return callmany


async def main():
    # amount = 278660378830953050
    # block_number = 16243694
    # to = '0x9420224D92bc1A214B47A6828a01715bC01E365e'
    # from_ = '0x6F37Dc59C3E4511a2f3ac2182F780a6B2B85CadC'
    # token = '0x45804880De22913dAFE09f4980848ECE6EcbAf78'

    amount = 20017436494191
    from_ = '0xa5CA6db3a0556B95795459C8b3b550c05fF29406'
    to = '0x4b657fc1DC695C82A25e4e29F6F7A811D9B72A15'
    token = '0xC5a9BC46A7dbe1c6dE493E84A18f02E70E2c5A32'
    block_number = 16243892

    # NORI
    amount = 1004891005333286017993
    from_ = '0x7f8c1877Ed0DA352F78be4Fe4CdA58BB804a30dF'
    to = '0x000000000000000000000000000000000000dEaD'
    token = '0x79add5ef078345f52e156ad8337a8441e0229bfc'
    block_number = 13239752

    async with aiohttp.ClientSession() as session:
        result = await sim_transfer(session, block_number, token, from_, to, amount)
    pp.pprint(result)
    """
    {'id': 1,
     'jsonrpc': '2.0',
     'result': [[{'value': '0000000000000000000000000000000000000000000000000000000000000000'},
                 {'value': '0000000000000000000000000000000000000000000000000000000000000001'},
                 {'value': '0000000000000000000000000000000000000000000000000000114ba394fc2a'}]]}
    """
    data = result['result'][0]
    val0, val1 = Web3.toInt(hexstr=data[0]['value']), Web3.toInt(hexstr=data[-1]['value'])
    if val1 - val0 != amount:
        print(f"Token {token} has fees: {(val1 - val0) / amount}")
    """
    Token 0xC5a9BC46A7dbe1c6dE493E84A18f02E70E2c5A32 has fees: 0.9500000000000275
    """

if __name__ == "__main__":
    asyncio.run(main())
