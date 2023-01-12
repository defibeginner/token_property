import web3
import datetime
from web3 import Web3
import pandas as pd


# def getLatestBlockTimestamp():
#     latestBlock = web3.eth.get_block('latest')
#     latestBlockTimestamp = latestBlock.timestamp
#
#     return latestBlockTimestamp
#
#
# def getAverageBlockTime():
#     currentBlock = web3.eth.get_block('latest')
#     thenBlock = web3.eth.get_block(web3.eth.block_number - 500)
#
#     return float((currentBlock.timestamp - thenBlock.timestamp) / 500.0)
#
#
# def getBlockByTimestamp(timestamp):
#     latestBlockTimestamp = getLatestBlockTimestamp()
#     average_time = latestBlockTimestamp - timestamp
#     if average_time < 0: raise ValueError('timestamp given by you exceed current block timestamp!')
#     average_block = average_time / getAverageBlockTime()
#
#     return int(web3.eth.blockNumber - average_block)
#
#
# hours_24_ago = datetime.utcnow().timestamp() - 24 * 60 * 60
# print(hours_24_ago) #1644892963.530618
#
# block_24_ago = getBlockByTimestamp(hours_24_ago)
# print(block_24_ago) # Block: 15265950
#
# blockInfo = web3.eth.get_block(block_24_ago)
# print(blockInfo.timestamp) #1644893303


def estimate_block_number_by_time(t):
    w3 = Web3(Web3.HTTPProvider("https://eth-mainnet.alchemyapi.io/v2/sBFFXcfLNdXl-Ym71hIwfpvhzAtdLE2e"))
    block_number0 = w3.eth.get_block_number()
    t0 = w3.eth.get_block(block_number0, True)['timestamp']
    delta = 12
    block_number1 = 0
    while True:
        block_number1 = int(block_number0 - (t0 - t) / delta)
        t1 = w3.eth.get_block(block_number1, True)['timestamp']
        if t - delta <= t1 <= t + delta:
            break
        block_number0, t0 = block_number1, t1
    # print(block_number1, pd.to_datetime(t1*1e9, utc=True))
    return block_number1


if __name__ == '__main__':
    day = '2023-01-01'
    start_block_id = estimate_block_number_by_time(pd.to_datetime(day).timestamp())
    end_block_id = estimate_block_number_by_time((pd.to_datetime(day) + pd.Timedelta('1D')).timestamp())

    w3 = Web3(Web3.HTTPProvider("https://eth-mainnet.alchemyapi.io/v2/sBFFXcfLNdXl-Ym71hIwfpvhzAtdLE2e"))
    t1 = w3.eth.get_block(start_block_id, True)['timestamp']
    print(start_block_id, pd.to_datetime(t1*1e9, utc=True))
    t1 = w3.eth.get_block(end_block_id, True)['timestamp']
    print(end_block_id, pd.to_datetime(t1*1e9, utc=True))


# 20230112-00:17:13.903999|INFO|TransferCost:search_transfer_1tran
# 2023-01-12 00:44:39.580606: 16312376, 0xf378005f4d34e11510f0ecf6548fbbb8ebb5d95e9d57cb493d99684a0650ef90

# 20230112-13:56:59.462696
# 2023-01-12 14:12:22.070830: 16315362, 0xeb557bfd6f5437fad301d99d783ef7ad6261d26f7fb1ec4663a482881320b4e7

