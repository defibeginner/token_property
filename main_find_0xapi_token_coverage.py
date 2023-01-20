
import os
import json
import requests
import numpy as np
import pandas as pd
from web3 import Web3
from web3 import exceptions
from math import log10, floor


def round_to_1(x):
    return round(x, -int(floor(log10(abs(x)))))


class TokenDetect(object):

    def __init__(self):
        _dir = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(_dir, 'configs/abi_erc20.json'), 'r') as f:
            self.erc20_abi = json.load(f)
        _rpc_url = 'https://eth-mainnet.alchemyapi.io/v2/sBFFXcfLNdXl-Ym71hIwfpvhzAtdLE2e'
        self.w3 = Web3(Web3.HTTPProvider(_rpc_url))

    def get_token_with_address(self, address):
        """
        :param address:
        """
        _token_address = Web3.toChecksumAddress(address)

        try:
            _token_contract = self.w3.eth.contract(address=_token_address, abi=self.erc20_abi)
            _symbol = _token_contract.functions.symbol().call()  # token symbol
            # TODO: OverflowError when it is used for MKR token
            # _token_contract.functions.name().call()  # token name
            _decimal = _token_contract.functions.decimals().call()  # token decimal
            return None, _symbol, _decimal
        except exceptions.InvalidAddress:
            return 'InvalidAddress', None, None
        except exceptions.BadFunctionCallOutput:
            return 'BadFunctionCallOutput', None, None
        except exceptions.ContractLogicError:
            return 'ContractLogicError', None, None
        except (Exception,) as e:
            return str(e), None, None


def find_dec_amt(add):
    # add = '0x514910771af9ca656af840dff83e8264ecf986ca'
    usdc = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
    sell_amt = int(10 * 10 ** 6)
    if add == usdc:
        return None, 6, 'USDC', 10
    if add == '0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2':
        return None, 18, 'MKR', 0.01

    e, sym, dec = d.get_token_with_address(add)
    if e is not None:
        return e, dec, sym, 0

    try:
        url = "https://api.0x.org/swap/v1/quote?buyToken=%s&sellToken=%s&sellAmount=%d" % (add, usdc, sell_amt)
        r = requests.get(url=url)
        res = json.loads(r.text)
        buy_amount = int(res['buyAmount'])
        buy_amt = round_to_1(float(buy_amount / 10 ** dec))
    except (Exception,) as e:
        return e, dec, sym, 0
    return None, dec, sym, buy_amt


def find_token_coverage():
    # https://metabase.spaceship.0x.org/question/3534-top-transaction-pairs-eth-with-running-totals
    filename = 'test/top_transaction_pairs_eth_with_running_totals_2022-12-06T21_54_42.456775Z.csv'
    df = pd.read_csv(filename)
    df.index = df.pair

    # np.cumsum(df.api_txn_30d_pair / df.api_txn_30d_pair.sum())
    trades_prct = df.running_total_api_txn_30d_pair_pct
    volume_prct = df.running_total_api_volume_30d_all_pair_pct

    res = pd.DataFrame(columns=['num_tokens', 'num_actual_pairs', 'max_num_pairs',
                                'min_0xApi_calls', 'max_0xApi_calls',
                                'api_volume_prct', 'api_txn_prct'])
    percents = [0.9, 0.95, 0.99, 0.999, 0.9999]
    pairs_res = dict()
    for pr in percents:
        i_max = np.argmax(volume_prct >= pr)
        vol_pr = pr
        txn_pr = trades_prct.iloc[i_max]

        n_pairs = i_max + 1

        tokens = list()
        pairs = set()
        for i in range(n_pairs):
            if type(df.pair_address.iloc[i]) is float and np.isnan(df.pair_address.iloc[i]):
                continue
            sym = df.pair_address.iloc[i]
            j = sym.find('-')
            p1, p2 = sym[:j], sym[j+1:]
            # sym1, sym2 = df.pair.iloc[i].split('-')
            if p1 < p2:
                pair = f'{p1}-{p2}'
            else:
                pair = f'{p2}-{p1}'
            pairs.add(pair)

            if p1 not in tokens:
                tokens.append(p1)
            if p2 not in tokens:
                tokens.append(p2)
        n_tokens = len(tokens)

        pairs_res[pr] = list(pairs)

        max_n_pairs = n_tokens * (n_tokens - 1) / 2

        max_0xapi_calls = 24 * 60 * 60 / 12 * 2 * n_pairs

        min_counts = (4*3/2) + (n_tokens - 4 - 1)
        min_0xapi_calls = 24 * 60 * 60 / 12 * min_counts

        res.loc[len(res)] = [n_tokens, n_pairs, max_n_pairs, min_0xapi_calls, max_0xapi_calls, vol_pr, txn_pr]
    res.to_csv('test/token_coverage.csv')

    json_object = json.dumps(pairs_res)
    with open("test/token_coverage.json", "w") as outfile:
        outfile.write(json_object)


if __name__ == '__main__':

    filename = 'top_transaction_pairs_eth_with_running_totals_2023-01-18T15_50_54.037119Z.csv'
    # this file is downloaded from
    # https://metabase.spaceship.0x.org/question/3534-top-transaction-pairs-eth-with-running-totals

    df = pd.read_csv(filename)

    addresses = set()
    for i in range(len(df)):
        add1, add2 = df.pair_address.iloc[i].split('-')
        # sym1, sym2 = df.pair.iloc[i].split('-')
        if add1 not in addresses:
            addresses.add(add1)
        if add2 not in addresses:
            addresses.add(add2)

    d = TokenDetect()
    # print(d.get_token_with_address('0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2'))
    # print(find_dec_amt('0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2'))

    result = pd.DataFrame(columns=['symbol', 'address', 'decimal', 'order_size', 'err'])
    for i, add in enumerate(addresses):
        e, dec, sym, buy_amt = find_dec_amt(add)
        if e is None:
            result.loc[len(result)] = [sym, add, dec, str([buy_amt]), str(e)]
        print([sym, add, dec, buy_amt, str(e)])
    result.to_csv('configs/token_list_0xapi_eth.csv', index=False)
