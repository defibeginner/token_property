import json
import pandas as pd
import numpy as np


def values_equal(x, y):
    if len(x) != len(y):
        return False
    for i in range(len(x)):
        if x[i] - y[i] > 1 or y[i] - x[i] > 1:
            return False
    return True


def get_fee_value(amount_out, amount_trans):
    """
    sim_result = [{'amount': 18789507722288, 'amount_out': 18789507722288, 'amount_in': 9582648938367},
                  {'amount': 7527122227138, 'amount_out': 7527122227138, 'amount_in': 3838832335841},
                  {'amount': 145410737490143, 'amount_out': 145410737490143, 'amount_in': 74159476119973},
                  {'amount': 45833242489386, 'amount_out': 45833242489386, 'amount_in': 23374953669587},
                  {'amount': 7526989113272, 'amount_out': 7526989113272, 'amount_in': 3838764447769}
                  ]

    :param amount_out:
    :param amount_trans:
    :return:
    """
    fee = [0 for _ in amount_out]
    fee_ratio = [0.0 for _ in amount_out]
    for i in range(len(amount_out)):
        # TODO: a potential error: 'Python int too large to convert to C long'
        fee[i] = amount_out[i] - amount_trans[i] if amount_out[i] > amount_trans[i] else amount_trans[i] - amount_out[i]
        try:
            fee_ratio[i] = np.round(fee[i] / amount_trans[i], 9)  # TODO hardcoded 9 decimal points
        except (Exception,) as e:
            return 'Unknown', '', '', 'overflow error'
    fee_uniq = set(fee)
    fee_ratio_uniq = set(fee_ratio)
    # unable to identify fee type if there is only 1 transfer
    if len(amount_trans) == 1:
        return 'FixedOrFractional', str(fee[0]), str(fee_ratio[0]), '1 trx'
    # unknown (but report fractional)
    if len(fee_uniq) == 1 and len(fee_ratio_uniq) == 1:
        return 'FixedOrFractional', str(fee[0]), str(fee_ratio[0]), '1 trx'
    # fixed
    if len(fee_uniq) == 1 and len(fee_ratio_uniq) > 1:
        return 'Fixed', str(fee[0]), '', ''
    # franctional
    if len(fee_uniq) > 1 and len(fee_ratio_uniq) == 1:
        return 'Fractional', '', str(fee_ratio[0]), ''
    # not fot
    # if len(fee_uniq) > 1 and len(fee_ratio_uniq) > 1:
    return 'Unknown', str(fee_uniq), str(fee_ratio_uniq), 'fee is changing'


def is_fot(sim_result):
    """
    inclusive fee-on-transfer: receiver receives fewer amounts
    exclusive fee-on-transfer: sender outputs more amounts

    :param sim_result:
    :return:
    """
    if len(sim_result) == 0:
        return {'is_fot': '', 'fot_type': '', 'fee_type': '',
                'sender_fee': '', 'sender_fee_ratio': '',
                'receiver_fee': '', 'receiver_fee_ratio': '', 'error': 'no trx'}

    amount = [res['amount'] for res in sim_result]
    amount_out = [res['amount_out'] for res in sim_result]
    amount_in = [res['amount_in'] for res in sim_result]
    zeros = [0 for _ in sim_result]

    if values_equal(amount_out, zeros) or values_equal(amount_in, zeros):
        return {'is_fot': 'Unknown', 'fot_type': '', 'fee_type': '',
                'sender_fee': '', 'sender_fee_ratio': '',
                'receiver_fee': '', 'receiver_fee_ratio': '', 'error': 'amount is 0'}

    out_amount_same = values_equal(amount_out, amount)
    in_amount_same = values_equal(amount_in, amount)
    if out_amount_same and in_amount_same:
        return {'is_fot': 'No', 'fot_type': '', 'fee_type': '',
                'sender_fee': '', 'sender_fee_ratio': '',
                'receiver_fee': '', 'receiver_fee_ratio': '', 'error': ''}

    if out_amount_same and not in_amount_same:
        fot_type = 'Inclusive'
        fee_type, receiver_fee, receiver_fee_ratio, e = get_fee_value(amount_in, amount)
        sender_fee, sender_fee_ratio = '', ''
    elif not out_amount_same and in_amount_same:
        fot_type = 'Exclusive'
        fee_type, sender_fee, sender_fee_ratio, e = get_fee_value(amount_out, amount)
        receiver_fee, receiver_fee_ratio = '', ''
    else:
        fot_type = 'BothInclusiveAndExclusive'
        fee_type1, receiver_fee, receiver_fee_ratio, e = get_fee_value(amount_in, amount)
        fee_type2, sender_fee, sender_fee_ratio, _ = get_fee_value(amount_out, amount)
        fee_type = f'{fee_type1} | {fee_type2}'
    return {'is_fot': 'Yes', 'fot_type': fot_type, 'fee_type': fee_type,
            'sender_fee': sender_fee, 'sender_fee_ratio': sender_fee_ratio,
            'receiver_fee': receiver_fee, 'receiver_fee_ratio': receiver_fee_ratio, 'error': e}


if __name__ == '__main__':
    filename = 'results/fee_on_transfer/fee_on_transfer_v3.log'
    df = pd.DataFrame(columns=['address', 'is_fot', 'fot_type', 'fee_type',
                               'sender_fee', 'sender_fee_ratio', 'receiver_fee', 'receiver_fee_ratio',
                               'error', 'sim_result'])
    with open(filename) as f:
        for line in f:
            line = line[:-1]
            line = line[line.find('{'):]
            data = json.loads(line)
            ret = is_fot(data.get('sim_result', []))
            df.loc[len(df)] = [data['token'],
                               ret.get('is_fot', ''),
                               ret.get('fot_type', ''),
                               ret.get('fee_type', ''),
                               ret.get('sender_fee', ''),
                               ret.get('sender_fee_ratio', ''),
                               ret.get('receiver_fee', ''),
                               ret.get('receiver_fee_ratio', ''),
                               ret.get('error', ''),
                               json.dumps(data.get('sim_result', ''))]
    df.to_csv('results/fee_on_transfer/fee_on_transfer_3.csv', index=False)
