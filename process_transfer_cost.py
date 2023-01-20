#!/usr/bin/env python

"""
main script of pricing api
"""

import os
import warnings
import pprint
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
from utils import AsyncLogger
from web3._utils.events import EventLogErrorFlags
from sklearn.cluster import KMeans
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec

# this is required for disabling image show
matplotlib.use('Agg')

__author__ = "yun"
__copyright__ = ""
__credits__ = ""
__license__ = ""
__version__ = ""
__maintainer__ = ""
__email__ = ""
__status__ = ""


def read_log(_filename):
    columns = ['txid', 'block_id', 'chain_id', 'status', 'trans_type', 'from', 'to',
               'gas_price_wei', 'gas_fee_base_wei', 'gas_fee_max_wei', 'gas_fee_max_priority_wei',
               'gas_limit', 'gas_used', 'burnt_wei', 'transaction_fee_wei',
               'sender', 'recipient', 'transfer_token', 'transfer_amount_wei', 'err']

    df = pd.DataFrame(columns=columns)
    with open(_filename) as f:
        for line in f:
            line = line[:-1]
            line = line[line.find('{'):]
            trx = json.loads(line)

            err = trx['error']
            status = trx.get('status', '')
            txid = trx['txid']
            if err is not None:
                df.loc[len(df)] = [txid, np.nan, '', status, '', '', '',
                                   np.nan, np.nan, np.nan, np.nan,
                                   np.nan, np.nan, np.nan, np.nan,
                                   '', '', '', np.nan, err]
                continue
            if status != 'confirmed':
                df.loc[len(df)] = [txid, np.nan, '', status, '', '', '',
                                   np.nan, np.nan, np.nan, np.nan,
                                   np.nan, np.nan, np.nan, np.nan,
                                   '', '', '', np.nan, 'trx not confirmed']
                continue
            logs = trx['logs']
            if len(logs) == 0:
                df.loc[len(df)] = [trx['txid'], trx['block_id'], trx['chain_id'], trx['status'], trx['trans_type'],
                                   trx['from'], trx['to'],
                                   trx['gas_price_wei'], trx['gas_fee_base_wei'], trx['gas_fee_max_wei'],
                                   trx['gas_fee_max_priority_wei'],
                                   trx['gas_limit'], trx['gas_used'], trx['burnt_wei'], trx['transaction_fee_wei'],
                                   '', '', '', np.nan, 'cannot identify logs']
                continue
            if len(logs) > 1:
                trx_tokens = np.unique([log['transfer_token'] for log in logs])
                trx_token = trx_tokens[0] if len(trx_tokens) == 1 else ''
                df.loc[len(df)] = [trx['txid'], trx['block_id'], trx['chain_id'], trx['status'], trx['trans_type'],
                                   trx['from'], trx['to'],
                                   trx['gas_price_wei'], trx['gas_fee_base_wei'], trx['gas_fee_max_wei'],
                                   trx['gas_fee_max_priority_wei'],
                                   trx['gas_limit'], trx['gas_used'], trx['burnt_wei'], trx['transaction_fee_wei'],
                                   '', '', trx_token, np.nan, 'multi transfers']
                continue
            log = logs[0]
            df.loc[len(df)] = [trx['txid'], trx['block_id'], trx['chain_id'], trx['status'], trx['trans_type'],
                               trx['from'], trx['to'],
                               trx['gas_price_wei'], trx['gas_fee_base_wei'], trx['gas_fee_max_wei'],
                               trx['gas_fee_max_priority_wei'],
                               trx['gas_limit'], trx['gas_used'], trx['burnt_wei'], trx['transaction_fee_wei'],
                               log['from'], log['to'], log['transfer_token'], log['amount_wei'], '']

    _out_filename = _filename.replace('.log', '.csv')
    df.to_csv(_out_filename, index=False)
    return df


def plot_hist_transfer_cost_1token(df3, token, symbol, labels):
    num_bins = 70
    num_samples = len(df3)

    labels_uniq = np.unique(labels)
    x_ticks = np.sort([df3[labels == label].gas_used.median() for label in labels_uniq])
    x_tick_labels = ['%.0f\n+%.0f' % (i, i - x_ticks[0]) for i in x_ticks]

    fig = plt.figure(figsize=(15, 12))
    gs = GridSpec(3, 1, width_ratios=[1], height_ratios=[1, 1, 1], wspace=0.4, hspace=0.4)
    # histogram of gas-limit
    ax = fig.add_subplot(gs[0])
    _, bin_edges = np.histogram(df3.gas_limit, bins=num_bins)
    x_bars = (bin_edges[:-1] + bin_edges[1:]) / 2
    width = (bin_edges[1] - bin_edges[0]) * 0.9
    cum_bar_heights = np.zeros(num_bins)
    for label in labels_uniq:
        y, _ = np.histogram(df3[labels == label].gas_limit, bins=bin_edges)
        y = y / num_samples
        ax.bar(x_bars, y, width=width, bottom=cum_bar_heights)
        cum_bar_heights += y
    ax.set_title(symbol)
    ax.set_ylabel('Percents of Samples')
    ax.set_xlabel('Gas-Limit')
    # histogram of gas-used
    ax = fig.add_subplot(gs[1])
    _, bin_edges = np.histogram(df3.gas_used, bins=num_bins)
    x_bars = (bin_edges[:-1] + bin_edges[1:]) / 2
    width = (bin_edges[1] - bin_edges[0]) * 0.9
    cum_bar_heights = np.zeros(num_bins)
    for label in labels_uniq:
        y, _ = np.histogram(df3[labels == label].gas_used, bins=bin_edges)
        y = y / num_samples
        ax.bar(x_bars, y, width=width, bottom=cum_bar_heights)
        cum_bar_heights += y
    # n, bins, patches = ax.hist(df3.gas_used, num_bins, facecolor='tab:blue', alpha=0.5, density=True)
    ax.set_ylabel('Percents of Samples')
    ax.set_xlabel('Gas-Used')
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(x_tick_labels, rotation=0)
    # scatter plot of gas-used
    ax = fig.add_subplot(gs[2])
    gas_used_ratio = df3.gas_used.values / df3.gas_limit.values
    ind = np.argsort(gas_used_ratio)
    gas_used_ratio_sort = gas_used_ratio[ind]
    labels_sort = labels[ind]
    for label in labels_uniq:
        ax.scatter(np.arange(num_samples)[labels_sort == label],
                   gas_used_ratio_sort[labels_sort == label], marker='x', s=20)
    # ax.legend()
    ax.set_ylabel('Gas-Used / Gas-Limit')
    ax.set_xlabel('Trx (sorted by the gas used ratio)')
    # ---- save ----
    fig_filename = f'results/trans_cost/fig_trans_cost_hist_{symbol}.png'
    fig.savefig(fig_filename)
    plt.close(fig)
    print(fig_filename)


def find_avg_cost_1token(df, token, erc20_abi, n_clusters=4, plot=False):
    try:
        w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
        contract = w3.eth.contract(address=token, abi=erc20_abi)
        symbol = contract.functions.symbol().call()
        # TODO: OverflowError when it is used for MKR token
        # _token_contract.functions.name().call()  # token name
        decimal = contract.functions.decimals().call()  # token decimal
    except (Exception,) as e:
        warnings.warn(f'{token}: {e}')
        symbol = token

    # find the trx with the given token
    df1 = df[(df.to == token) | (df.transfer_token == token)]

    # identify if there are multiple transfers
    df2 = df1[df1.err == 'multi transfers']
    if len(df2) > 0:
        multi_trans = True
    else:
        multi_trans = False

    # uniq trans and confirmed
    # df3 = df1[(df1.err == '') & (df1.status == 'confirmed')]
    df3 = df1[df1.status == 'confirmed']

    num_trx = len(df3)

    # find the gas-used
    if len(df3) < 4:
        labels = np.arange(len(df3))
    else:
        x = df3.gas_used.values.reshape(-1, 1)
        kmeans = KMeans(n_clusters=n_clusters, random_state=0).fit(x)
        labels = kmeans.labels_

    # avg_gas = np.sort(kmeans.cluster_centers_.flatten())
    labels_uniq = np.unique(labels)
    avg_gas = np.sort([df3[labels == label].gas_used.median() for label in labels_uniq])
    if len(labels_uniq) < 4:
        avg_gas1 = np.full(4, np.nan)
        avg_gas1[:len(avg_gas)] = avg_gas
    else:
        avg_gas1 = avg_gas

    x = []
    for label in labels_uniq:
        x.append(df3[labels == label].iloc[:1].copy())
    x = pd.concat(x)
    x.to_csv(f'results/trans_cost/abnormal_cases/abnormal_case_{symbol}.csv')


    if plot:
        plot_hist_transfer_cost_1token(df3, token, symbol, labels)

    return symbol, num_trx, multi_trans, avg_gas1


def find_avg_cost(df, token_list):

    with open(os.path.join('configs/abi_erc20.json'), 'r') as f:
        erc20_abi = json.load(f)

    # tokens = list(set(list(df.to.unique())).union(set(list(df.transfer_token.unique()))))
    # freq = np.zeros(len(tokens))
    # for i, t in enumerate(tokens):
    #     freq[i] = sum(df.to == t)
    counts = df.to.value_counts()
    tokens_onchain = np.array(list(counts.index))
    # freq = counts.values

    # find out percentage of coverage
    tokens_onchain = pd.DataFrame(data={'token_address': counts.index, 'num_transfers': counts.values})
    trade_at_0xapi = np.full(len(tokens_onchain), False)
    found_trx = np.full(len(token_list), False)
    for i in range(len(tokens_onchain)):
        add = tokens_onchain.token_address.iloc[i].lower()
        # trade_at_0xapi[i] = token_list.address.str.contains(add).any()
        temp = token_list[token_list.address == add]
        if len(temp) == 0:
            trade_at_0xapi[i] = 0
        else:
            trade_at_0xapi[i] = True
            found_trx[temp.index[0]] = True
    token_list['trx_found'] = found_trx
    token_list.to_csv('results/trans_cost/_token_list_0xapi.csv', index=False)
    print(sum(found_trx), len(found_trx), sum(found_trx) / len(found_trx))
    tokens_onchain['traded_at_0xapi'] = trade_at_0xapi
    tokens_onchain.to_csv('results/trans_cost/_token_list_onchain.csv', index=False)
    print(sum(trade_at_0xapi), len(trade_at_0xapi), sum(trade_at_0xapi) / len(trade_at_0xapi))

    #
    #
    res = pd.DataFrame(columns=['symbol', 'address', 'num_trx', 'multi_trx',
                                'avg_gas0', 'avg_gas1', 'avg_gas2', 'avg_gas3'])
    plot = False
    n = 0
    for i in range(len(tokens_onchain)):
        if not tokens_onchain.traded_at_0xapi.iloc[i]:
            continue
        # token = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
        token = tokens_onchain.token_address.iloc[i]
        symbol, num_trx, multi_trans, avg_gas = find_avg_cost_1token(df, token, erc20_abi, n_clusters=5, plot=plot)
        res.loc[len(res)] = [symbol, token, num_trx, multi_trans] + list(avg_gas)
        print(symbol, num_trx, multi_trans, avg_gas)
        n += 1
        if n == 100:
            print('-----------------------------', i, len(tokens_onchain))
            n = 0
    csv_filename = f'results/trans_cost/_tab_trans_cost.csv'
    res['gas5']=np.full(len(res), np.nan)
    res['gas1-gas0'] = res.avg_gas1 - res.avg_gas0
    res['gas3-gas2'] = res.avg_gas3 - res.avg_gas2
    res['gas2-gas0'] = res.avg_gas2 - res.avg_gas0
    res['gas3-gas1'] = res.avg_gas3 - res.avg_gas1
    res.to_csv(csv_filename, index=False)

    # special case
    token = '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984'  # uni


if __name__ == '__main__':

    # filename = 'results/trans_cost/transfer_cost_2023-01-02.log'
    # _df = read_log(filename)

    # -------------------- process logs --------------------
    # days = pd.date_range('2022-12-11', '2022-12-23', freq='1D')
    # for day in days:
    #     print(f'now {day}')
    #     filename = 'results/trans_cost/transfer_cost_{}.log'.format(day.date())
    #     x = read_log(filename)
    #     print(f'{day} complete: len={len(x)}')

    # -------------------- process logs --------------------
    df = []
    days = pd.date_range('2022-12-11', '2023-01-10', freq='1D')
    for day in days:
        filename = 'results/trans_cost/transfer_cost_{}.csv'.format(day.date())
        x = pd.read_csv(filename)
        x = x[['txid', 'block_id', 'status', 'from', 'to',
               'gas_limit', 'gas_used', 'transfer_token', 'err']]
        df.append(x)
    df = pd.concat(df)

    # token list
    x = pd.read_csv('configs/token_list_0xapi_eth.csv')
    token_list = x[['symbol', 'address']].copy()

    find_avg_cost(df, token_list)

    #
