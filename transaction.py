from binascii import hexlify, unhexlify


class Transaction:
    """
    The transaction class is a factory class which do not have any functional methods.
    It's only used to generate a textbased coinbase.

    :param height: int, Height of the generated block
    :param coinbase_amount: int, coinbase amount in satoshi
    :param output_pubkey: hex, hash 160 of pubkey
    """
    def __init__(self, height, coinbase_amount, output_pubkey='4b7da9f99bac968111826ac177107ee046500db7'):
        #Converts parameters to little endian with the correct byte size.
        height = hexlify(height.to_bytes(3, byteorder='little', signed=False)).decode()
        satoshis = hexlify(coinbase_amount.to_bytes(8, byteorder='little', signed=False)).decode()
        # coinbase template, is a raw tx with txid 51286b72de4e7712cd614c34ae086afb0ac8532d83b361471e41dd86046af488, replaces the height and the pubkey
        self.coinbase_template = f'010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0403{height}ffffffff02{satoshis}1976a914{output_pubkey}88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000'

    def __str__(self):
        return self.coinbase_template

    def as_byte(self):
        return hexlify(unhexlify(self.coinbase_template))
