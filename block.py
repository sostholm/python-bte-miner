from binascii import hexlify, unhexlify
import hashlib


class Block:

    def __init__(self, previous_block_header_hash, time, nbits,  merkle_root_hash='', nonce=0, raw_coinbase='', target=''):
        """
        Initiates the block data which is then obtained by calling __str__(), get_blockheader() and hash_header() 
        :param previous_block_header_hash: big endian hex
        :param time: int epoch
        :param nbits: hex, big endian
        :param merkle_root_hash: hex, big endian
        :param nonce: int
        :param raw_coinbase: hex, raw transaction for coinbase.
        :param target: hex, big endian
        """
        self.version = '01000000'
        #flips the byte order to little endian
        self.previous_block_header_hash = hexlify(unhexlify(previous_block_header_hash)[::-1]).decode()
        self.merkle_root_hash = hexlify(unhexlify(merkle_root_hash)[::-1]).decode()
        self.time = hexlify(time.to_bytes(4, byteorder='little', signed=False)).decode()
        self.nbits = hexlify(unhexlify(nbits)[::-1]).decode()
        self.nonce_int = nonce
        self.lowest_nonce = nonce
        self.nonce = hexlify(nonce.to_bytes(4, byteorder='little', signed=False)).decode()
        #0xFD for variable int of 1 byte, 01 is 1 tx
        self.txn_count = '01'
        self.raw_coinbase = raw_coinbase
        self.target = target

    def __str__(self):
        """
        Prints the block data when print(block) is called.
        :return: string, block data.
        """
        return self.version + self.previous_block_header_hash + self.merkle_root_hash + self.time  \
            + self.nbits + self.nonce + self.txn_count + self.raw_coinbase

    def print_verbose(self):
        """
        Names all data from the block.
        :return: String
        """
        return 'version: ' + self.version + '\nprev_block_header: ' + self.previous_block_header_hash + \
               '\n merkle root: ' + self.merkle_root_hash + '\ntime: ' + self.time  \
                + '\nnbits: ' + self.nbits + '\nnonce: ' + self.nonce + '\ntx count: ' + self.txn_count + \
               '\nraw transaction: ' + self.raw_coinbase

    def get_blockheader(self):
        """
        Used to get only the header data
        :return: String
        """
        return self.version + self.previous_block_header_hash + self.merkle_root_hash + self.time \
               + self.nbits + self.nonce

    def increment_nonce(self):
        """
        Increases the nonce by one and converts the new nonce to hex and little endian with the correct byte-size.
        :return: None
        """
        self.nonce_int += 1
        self.nonce = hexlify(self.nonce_int.to_bytes(4, byteorder='little', signed=False)).decode()

    def set_nonce(self, nonce):
        """
        Used to recreate the lowest block that was found.
        :param nonce: int
        :return: None
        """
        self.nonce_int = nonce
        self.nonce = hexlify(self.nonce_int.to_bytes(4, byteorder='little', signed=False)).decode()

    def hash_header(self):
        """
        Performs dsha256 and converts the result to little endian.
        :return: hex
        """
        header_byte = unhexlify(self.get_blockheader())
        return hexlify(hashlib.sha256(hashlib.sha256(header_byte).digest()).digest()[::-1]).decode()

    def mine_block(self, args):
        """
        Performs dsha256 on the header and compares if it's less than the target (difficulty), and saves the lowest hash that was found and it's nonce.
        :param args: tuple, (int, int) (initial nonce, attempts)
        :return: tuple, (target_found, block)
        """

        self.nonce_int = args[0]
        attempts = args[1]
        #initiates a high hash
        header_hash = 'c3cb000000000000000000000000000000000000000000000000000000000000'

        #If the target has been found or if attemppts is out, cancel loop.
        while header_hash >= self.target and attempts > 0:
            new_hash = self.hash_header()

            if new_hash < header_hash:
                header_hash = new_hash
                self.lowest_nonce = self.nonce_int
            else:
                self.increment_nonce()
                attempts -= 1

        #make sure that the object's nonce is the lowest
        self.set_nonce(self.lowest_nonce)

        #If the block has been found, print some data and return "True"
        if header_hash < self.target:
            print('Woohoo!!!: ' + header_hash)
            print(self.__str__())
            print(self.print_verbose())
            return True, self
        else:
            print('final hash: ' + header_hash)
            return False, self


