
import json
import pandas as pd
import numpy as np


def temp_find_results_combo():
    x = ['' for i in range(len(df))]
    for i in range(len(df)):
        found_permit_func = df.permit_func.iloc[i]
        found_signature = df.signature.iloc[i]
        found_nonces = df.nonces.iloc[i] or df.nonces_func.iloc[i]
        found_domain_separator = df.domain_separator.iloc[i] or df.domain_separator_func.iloc[i]
        x[i] = f'{found_permit_func}-{found_signature}-{found_nonces}-{found_domain_separator}'
    """
    'False-False-False-False',   -- not permit
    'False-False-False-True',   -- not permit; domain separator is used in Ownable
    'False-False-True-False',   -- not permit. nonce is used for different purposes, such as ownable, burn,  
    'False-True-False-False',   -- not permit; signature is used in mint() and defined in ECDSA library
    'False-False-True-True',   -- not permit; just found one such token, and nonces and domain separator are never used in the contract
    'False-True-False-True',   -- not permit. just found 1 such token. signature and domain separator are used in claim() that does mint()
    'False-True-True-False',   -- not permit. just found 2 such tokens. Signature and nonces are used in claim(). It does NOT use ecrecover to verify the signature.
    'False-True-True-True',   -- not permit. there are a lot of such tokens. signature, nonces, dom-sep are used for delegate()
    'True-False-True-False',  -- ???? there are 2 cases, not known yet, need to double check
    'True-False-True-True',  -- a lot of such tokens
    'True-True-True-True'       ------------ yes
    """


if __name__ == '__main__':
    # get the list of 1inch
    filename = 'configs/1inch_permit_tokens_eth.csv'
    df_1inch = pd.read_csv(filename)
    list_permit_1inch = [s.lower() for s in df_1inch.address.values]

    # get the list of 0x
    filename = 'configs/0x_current_permit_tokens_eth.json'
    with open(filename) as f:
        data = json.load(f)
    list_permit_0x = list(data.keys())

    # filename = 'results/permit/permit_v3.log'
    # df = pd.DataFrame(columns=['symbol', 'address', 'impl_contract', 'permit_in_abi', 'permit_func', 'signature',
    #                            'nonces', 'nonces_func', 'found_domain_separator', 'found_domain_separator_func',
    #                            'error', 'is_permit_from_our_result', 'permit_type', 'domain_separator', 'domain'])
    # with open(filename) as f:
    #     for line in f:
    #         line = line[:-1]
    #         line = line[line.find('{'):]
    #         data = json.loads(line)
    #         df.loc[len(df)] = [data['symbol'],
    #                            data['address'],
    #                            data['impl_contract'],
    #                            data.get('permit_in_abi', ''),
    #                            data.get('permit_func', ''),
    #                            data.get('signature', ''),
    #                            data.get('nonces', ''),
    #                            data.get('nonces_func', ''),
    #                            data.get('found_domain_separator', ''),
    #                            data.get('found_domain_separator_func', ''),
    #                            data['error'],
    #                            data.get('is_permit', ''),
    #                            data.get('permit_type', ''),
    #                            data.get('domain_separator', ''),
    #                            json.dumps(data.get('domain', '')),
    #                            ]
    # df.to_csv('results/permit/permit_7.csv', index=False)

    filename = 'results/permit/permit.log'
    df = pd.DataFrame(columns=['symbol', 'address', 'impl_contract', 'error',
                               'is_permit_from_our_result', 'permit_type', 'domain_separator',
                               'name', 'version', 'chainid', 'verifyingcontract', 'salt'])
    with open(filename) as f:
        for line in f:
            line = line[:-1]
            line = line[line.find('{'):]
            data = json.loads(line)
            domain = data.get('domain', {})
            if domain is None:
                domain = {}
            df.loc[len(df)] = [data['symbol'],
                               data['address'],
                               data['impl_contract'],
                               data.get('error', ''),
                               data.get('is_permit', ''),
                               data.get('permit_type', ''),
                               data.get('domain_separator', ''),
                               domain.get('name', ''),
                               domain.get('version', ''),
                               domain.get('chainId', ''),
                               domain.get('verifyingContract', ''),
                               domain.get('salt', ''),
                               ]
    # df.to_csv('results/permit/permit_7.csv', index=False)

    # permit = ['' for _ in range(len(df))]
    # for i in range(len(df)):
    #     found_permit_func = df.permit_func.iloc[i]
    #     found_signature = df.signature.iloc[i]
    #     found_nonces = df.nonces.iloc[i] or df.nonces_func.iloc[i]
    #     found_domain_separator = df.domain_separator.iloc[i] or df.domain_separator_func.iloc[i]
    #     if not found_permit_func:
    #         permit[i] = 'No'
    #         continue
    #     if found_permit_func and found_signature and found_nonces and found_domain_separator:
    #         permit[i] = 'Yes'
    #     else:
    #         permit[i] = '?'
    # df['manual_check_result'] = permit
    # df.to_csv('results/permit/permit_4_manual_check.csv', index=False)

    oneinch = ['' for _ in range(len(df))]
    for add in list_permit_1inch:
        ind = np.where((df.address == add) | (df.impl_contract == add))[0]
        if len(ind) > 1:
            oneinch[ind[0]] = 'TRUE'
        if len(ind) == 1:
            oneinch[ind[0]] = 'TRUE'
        if len(ind) == 0:
            print(add)
    df['is_permit_from_1inch'] = oneinch
    zerox = ['' for _ in range(len(df))]
    for add in list_permit_0x:
        ind = np.where((df.address == add) | (df.impl_contract == add))[0]
        if len(ind) > 1:
            zerox[ind[0]] = 'TRUE'
        if len(ind) == 1:
            zerox[ind[0]] = 'TRUE'
        if len(ind) == 0:
            print(add)
    df['is_permit_from_0x'] = zerox
    df.index.name = 'id'
    df.to_csv('results/permit/permit_14.csv', index=True)

    # check
    filename = 'configs/0x_current_permit_tokens_eth.json'
    with open(filename) as f:
        data = json.load(f)
    for key, val in data.items():
        df1 = df[df.address == key]
        if len(df1) == 0:
            continue
        domain = val['domain']
        domain2 = {'name': df1.iloc[0]['name'],
                   'version': df1.iloc[0].version,
                   'chainId': df1.iloc[0].chainid,
                   'verifyingContract': df1.iloc[0].verifyingcontract,
                   'salt': df1.iloc[0].salt,
                   }
        domain2 = {k: v for k, v in domain2.items() if v is not None and v != ''}
        if val['domainSeparator'] != df1.iloc[0].domain_separator:
            print('error', key)
        if domain != domain2:
            print('error', key)
