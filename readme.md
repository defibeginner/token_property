

## token property 

### transfer cost

1. run `main_transfer_cost.py` to get all transfer history
    ```commandline
    python main_transfer_cost.py 2023-01-02
    ```
   (note that `main_transfer_cost_async.py` is async version that needs more revision)
2. run `process_transfer_cost.py` to process the logs and `csv` files of transfers.
   (with the `read_log()` uncommented)
3. run `process_transfer_cost.py` to find the transfer gasses.
   (with the `find_avg_cost()` uncommented)
4. results are in `results/trans_cost/`


