#!/usr/bin/env python3
#
# Thomas Lundqvist, Oct 2018, use freely
#
# Code inspired and borrowed from:
#   https://www.ccn.com/block-parser-how-read-bitcoin-block-chain/
#   https://github.com/tenthirtyone/blocktools
#
# Uses:
#   import and call decodeBlock or decodeHeader
# or run on command line to read block from file:
#   decode_block.py bestblock.bin

import sys, io, binascii, struct, hashlib
from datetime import datetime

def uint1(stream):
    return ord(stream.read(1))
def uint2(stream):
    return struct.unpack('<H', stream.read(2))[0]
def int4(stream):
    return struct.unpack('<i', stream.read(4))[0]
def uint4(stream):
    return struct.unpack('<I', stream.read(4))[0]
def uint8(stream):
    return struct.unpack('<Q', stream.read(8))[0]
def hash32(stream):
    return stream.read(32)[::-1]

def time(stream):
    time = uint4(stream)
    return time

def varint(stream):
    size = uint1(stream)
    
    if size < 0xfd:
        return size
    if size == 0xfd:
        return uint2(stream)
    if size == 0xfe:
        return uint4(stream)
    if size == 0xff:
        return uint8(stream)
    return -1

def b2str(rawbytes):
    return binascii.hexlify(rawbytes).decode()

def decodeTime(time):
    utc_time = datetime.utcfromtimestamp(time)
    return utc_time.strftime("%Y-%m-%d %H:%M:%S.%f+00:00 (UTC)")

def dsha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

class BlockHeader:
    def __init__(self, blockchain):
        self.version = int4(blockchain)
        self.previousHash = hash32(blockchain)
        self.merkleHash = hash32(blockchain)
        self.time = uint4(blockchain)
        self.bits = uint4(blockchain)
        self.nonce = uint4(blockchain)
        blockchain.seek(0)
        self.hash = b2str(dsha256(blockchain.read(80))[::-1])
    def toString(self):
        print("Version:\t 0x%x" % self.version)
        print("Hash\t\t %s" % self.hash)
        print("Previous Hash\t %s" % b2str(self.previousHash))
        print("Merkle Root\t %s" % b2str(self.merkleHash))
        print("Time stamp\t "+ decodeTime(self.time))
        print("Difficulty\t 0x%08x" % self.bits)
        print("Nonce\t\t 0x%08x" % self.nonce)

class Tx:
    def __init__(self, blockchain):
        seekStart = blockchain.tell()
        self.version = uint4(blockchain)
        self.inCount = varint(blockchain)
        """"""
        self.witnessdata = False
        if self.inCount == 0:
            flag = uint1(blockchain)
            if flag == 1:
                self.witnessdata = True
                self.inCount = varint(blockchain)
            else:
                print('Error: unknown flag 0x%02x in tx' % flag)
        self.inputs = []
        self.seq = 1
        for i in range(self.inCount):
            input = txInput(blockchain)
            self.inputs.append(input)
        self.outCount = varint(blockchain)
        self.outputs = []
        if self.outCount > 0:
            for i in range(self.outCount):
                output = txOutput(blockchain)
                self.outputs.append(output)
        seekEndout = blockchain.tell()
        if self.witnessdata:
            self.witnesses = []
            self.witnessCount = varint(blockchain)
            for i in range(self.witnessCount):
                witness_data = txWitness(blockchain)
                self.witnesses.append(witness_data)
        self.lockTime = uint4(blockchain)
        seekEndtx = blockchain.tell()
        blockchain.seek(seekStart)
        rawtx = blockchain.read(seekEndout - seekStart) # skip possible segwit data
        if self.witnessdata:
            rawtx = rawtx[0:4] + rawtx[6:]  # remove segwit flag
        blockchain.seek(seekEndtx-4)
        rawtx += blockchain.read(4)  # finally, read lock time
        self.txid = b2str(dsha256(rawtx)[::-1])

    def toString(self):
        print()
        print("="*20 + " No. %s " %self.seq + "Transaction " + "="*20)
        print('Txid:\t\t %s' % self.txid)
        print("Tx Version:\t 0x%x" % self.version)
        print("Witness flag:\t %s" % self.witnessdata)

        print("Inputs:\t\t %d" % self.inCount)
        for i in self.inputs:
            i.toString()
        print("Outputs:\t %d" % self.outCount)
        for o in self.outputs:
            o.toString()
        if self.witnessdata:
            print("Witness chunks:\t %d" % self.witnessCount)
            for w in self.witnesses:
                w.toString()
        print("Lock Time:\t %d" % self.lockTime)

class txInput:
    def __init__(self, blockchain):
        self.prevhash = hash32(blockchain)
        self.previndex = uint4(blockchain)
        self.scriptLen = varint(blockchain)
        self.scriptSig = blockchain.read(self.scriptLen)
        self.seqNo = uint4(blockchain)
    def toString(self):
        print("\tPrev. Tx Hash:\t %s" % b2str(self.prevhash))
        if self.previndex == 0xffffffff:
            print("\tPrev. Index:\t %08x (coinbase)" % self.previndex)
        else:
            print("\tPrev. Index:\t %d" % self.previndex)
        print("\tScript Length:\t %d" % self.scriptLen)
        print("\tScriptSig:\t %s" % b2str(self.scriptSig))
        if self.previndex == 0xffffffff:
            print("\tScriptSig, txt:\t %s" % self.scriptSig)
        print("\tSequence:\t %8x" % self.seqNo)

class txOutput:
    def __init__(self, blockchain): 
        self.value = uint8(blockchain)
        self.scriptLen = varint(blockchain)
        self.pubkey = blockchain.read(self.scriptLen)
    def toString(self):
        print("\tValue:\t\t %d" % self.value + " satoshi")
        print("\tScript Len:\t %d" % self.scriptLen)
        print("\tScriptPubkey:\t %s" % b2str(self.pubkey))

class txWitness:
    def __init__(self, blockchain):
        self.dataLen = varint(blockchain)
        self.data = blockchain.read(self.dataLen)
    def toString(self):
        print("\tData length:\t %d" % self.dataLen)
        print("\tWitness data:\t %s" % b2str(self.data))
        
def decodeBlock(rawblock):
    raw = io.BytesIO(rawblock)
    header = BlockHeader(raw)
    print(header.toString())
    txCount = varint(raw)
    print(txCount)

    txs = []
    for i in range(txCount):
        tx = Tx(raw)
        tx.seq = i 
        txs.append(tx)
    
    print()
    print("#"*10 + " Block Header " + "#"*10)
    header.toString()
    print()
    print("##### Tx Count: %d" % txCount)
    for t in txs:
        t.toString()
    print("#### end of all %d transactions" % txCount)

    remaining = b2str(raw.read())
    if len(remaining) > 0:
        print("Remaining bytes:")
        print(remaining)


def decodeHeader(rawblock):
    raw = io.BytesIO(rawblock)
    header = BlockHeader(raw)
    
    print()
    print("#"*10 + " Block Header " + "#"*10)
    header.toString()
    print()

    remaining = b2str(raw.read())
    if len(remaining) > 0:
        print("Remaining bytes:")
        print(remaining)

# If run as command, read block from file

# Default file name:
BEST_BLOCK_FILE = 'bestblock.bin'

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    else:
        fname = BEST_BLOCK_FILE
    print('Reading binary block data from file:',fname)
    with open(fname, 'rb') as f:
        block = f.read()
        decodeBlock(block)
