import requests
import json
from block import Block
from transaction import Transaction
from binascii import hexlify,unhexlify
import os
from multiprocessing import Pool
from decode_block import *

"""
Author: Samuel Östholm, samuel.ostholm@student.hv.se
"""


class BteRpc:

    def __init__(self):
        """
        Initiates the RPC client.
        """
        self.rpc_user = '*******'
        self.rpc_pass = '*******'

        self.url = 'http://%s:%s@localhost:8332' % (self.rpc_user, self.rpc_pass)
        self.headers = {'content-type': 'application/json'}

    def rest_call(self, payload):
        """
        Send input to the RPC running on localhost
        :param payload:
        :return: json
        """
        response = requests.post(self.url, data=json.dumps(payload), headers=self.headers).json()
        return response

    def get_block_template(self):
        payload = {
            'method': 'getblocktemplate'
        }
        return self.rest_call(payload)['result']

    def decode_raw_transaction(self, tx_hex):
        """
        Takes a transaction in hex format and converts it to JSON.
        :param tx_hex:
        :return: JSON
        """
        payload = {
            'method': 'decoderawtransaction',
            'params': [tx_hex]
        }
        return self.rest_call(payload)['result']

    def submit_block(self, block_hex):
        """
        Sends a mined block to the network.
        :param block_hex:
        :return: JSON
        """
        payload = {
            'method': 'submitblock',
            'params': [block_hex]
        }
        return self.rest_call(payload)

    BEST_BLOCK_FILE = 'bestblock.bin'

    def writeblock(self, blockbin):
        """
        Outputs a blick to file.
        :param blockbin: block i byte format
        :return: None
        """
        print('Writing binary block data to:', BEST_BLOCK_FILE)
        with open(BEST_BLOCK_FILE, 'wb') as f:
            f.write(blockbin)

    def make_block(self):
        """
        Creates a block with height and coinbase from rpc call.
        Uses decode raw transaction to generate txid.
        :return: BTE Block object
        """
        block_template = self.get_block_template()

        coinbase_tx = Transaction(height=block_template['height'], coinbase_amount=block_template['coinbasevalue'])
        txid = self.decode_raw_transaction(coinbase_tx.__str__())['txid']
        block = Block(
            previous_block_header_hash=block_template['previousblockhash'],
            time=block_template['curtime'],
            nbits=block_template['bits'],
            nonce=0,
            raw_coinbase=coinbase_tx.__str__(),
            target=block_template['target'],
            merkle_root_hash=txid
        )

        return block

    def calculate_merkle(self, txid1, txid2):
        """
        Merkle root calulation, changes txid to little endian and runs dsha256 on the result.
        :param txid1: first transaction id
        :param txid2: second transaction id
        :return: hashad merkelroot
        """
        part1 = hexlify(unhexlify(txid1)[::-1]).decode()
        part2 = hexlify(unhexlify(txid2)[::-1]).decode()
        join = part1 + part2
        hash = hashlib.sha256(hashlib.sha256(unhexlify(join)).digest()).hexdigest()
        return hexlify(unhexlify(hash)).decode()

    def start_mine(self, attempts=500000):
        """
        Start mining.
        Uses a process pool for mining concurrency.
        Possible nonces is divided among the processes so they're not calculating the same hash.
        Also times from start to finish to output h/s.
        If the block is found, an rpc call is made in order to submitt the block to the network.

        Also prints the lowest hash with the raw data and the decoded block.
        :param attempts: int, the amount of attempts to try and find the block.
        :return: None
        """
        print('Mining...')

        #Creates the block
        block = self.make_block()

        #builds nonce array used as input for the processes
        max_nonce = 4294967295
        div_nonce = max_nonce / os.cpu_count()
        nonce_array = [(int(x * div_nonce), attempts) for x in range(4)]

        start_time = datetime.now()

        #Create process pool
        with Pool(os.cpu_count()) as p:
            x = p.map(block.mine_block, nonce_array, )
            for tup in x:
                #If a block is bigger than the target, submit to blockchain
                if True in tup:
                    print(rpc.submit_block(tup[1].__str__()))

            #Picks up all blocks returned from .
            final_blocks = [tup[1] for tup in x]
            final_hashes = [block1.hash_header() for block1 in final_blocks]

            #Find the lowest has of all blocks returned.
            lowest_hash = min(final_hashes)
            print('Lowest hash: ' + lowest_hash)

            #Find the lowest block.
            lowest_hash_block = final_blocks[final_hashes.index(lowest_hash)]

            raw_block = lowest_hash_block.__str__()

            #Prints, saves and decodes the lowest block.
            print('Raw block: ' + raw_block)
            raw_block_byte = unhexlify(raw_block)
            self.writeblock(raw_block_byte)
            decodeBlock(raw_block_byte)

            elapsed_time = datetime.now() - start_time
            hash_per_seconds = int(round(attempts / elapsed_time.seconds, 0) * os.cpu_count())
            print(str(hash_per_seconds) + ' hash/s')
            print('Mining finished: ' + str(round(elapsed_time.seconds/60, 2)) + 'm')


if __name__ == '__main__':

    rpc = BteRpc()
    rpc.start_mine(1000000)


