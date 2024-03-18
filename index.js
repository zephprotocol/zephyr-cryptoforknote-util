module.exports = require('bindings')('cryptoforknote.node');

const SHA3    = require('sha3');
const bignum  = require('bignum');
const bitcoin = require('bitcoinjs-lib');
const varuint = require('varuint-bitcoin');
const crypto  = require('crypto');
const fastMerkleRoot = require('merkle-lib/fastRoot');

const rtm = require('cryptoforknote-util/rtm');

function scriptCompile(addrHash) {
  return bitcoin.script.compile([
    bitcoin.opcodes.OP_DUP,
    bitcoin.opcodes.OP_HASH160,
    addrHash,
    bitcoin.opcodes.OP_EQUALVERIFY,
    bitcoin.opcodes.OP_CHECKSIG
  ]);
}

function reverseBuffer(buff) {
  let reversed = Buffer.alloc(buff.length);
  for (var i = buff.length - 1; i >= 0; i--) reversed[buff.length - i - 1] = buff[i];
  return reversed;
}

function txesHaveWitnessCommit(transactions) {
  return (
    transactions instanceof Array &&
    transactions[0] &&
    transactions[0].ins &&
    transactions[0].ins instanceof Array &&
    transactions[0].ins[0] &&
    transactions[0].ins[0].witness &&
    transactions[0].ins[0].witness instanceof Array &&
    transactions[0].ins[0].witness.length > 0
  );
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
};

function hash256(buffer) {
  return sha256(sha256(buffer));
};

function getMerkleRoot(transactions) {
  if (transactions.length === 0) return Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
  const forWitness = txesHaveWitnessCommit(transactions);
  const hashes = transactions.map(transaction => transaction.getHash(forWitness));
  const rootHash = fastMerkleRoot(hashes, hash256);
  return forWitness ? hash256(Buffer.concat([rootHash, transactions[0].ins[0].witness[0]])) : rootHash;
}

let last_epoch_number;
let last_seed_hash;

module.exports.baseDiff = function() {
  return bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);
};

module.exports.baseRavenDiff = function() {
  return parseInt('0x00000000ff000000000000000000000000000000000000000000000000000000');
};

module.exports.RavenBlockTemplate = function(rpcData, poolAddress) {
  const poolAddrHash = bitcoin.address.fromBase58Check(poolAddress).hash;

  let txCoinbase = new bitcoin.Transaction();
  let bytesHeight;
  { // input for coinbase tx
    let blockHeightSerial = rpcData.height.toString(16).length % 2 === 0 ?
                                  rpcData.height.toString(16) :
                            '0' + rpcData.height.toString(16);
    bytesHeight = Math.ceil((rpcData.height << 1).toString(2).length / 8);
    const lengthDiff  = blockHeightSerial.length/2 - bytesHeight;
    for (let i = 0; i < lengthDiff; i++) blockHeightSerial = blockHeightSerial + '00';
    const serializedBlockHeight = Buffer.concat([
      Buffer.from('0' + bytesHeight, 'hex'),
      reverseBuffer(Buffer.from(blockHeightSerial, 'hex')),
      Buffer.from('00', 'hex') // OP_0
    ]);

    txCoinbase.addInput(
      // will be used for our reserved_offset extra_nonce
      Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
      0xFFFFFFFF, 0xFFFFFFFF,
      Buffer.concat([serializedBlockHeight, Buffer.alloc(17, 0xCC)]) // 17 bytes
    );

    txCoinbase.addOutput(scriptCompile(poolAddrHash), Math.floor(rpcData.coinbasevalue));

    if (rpcData.default_witness_commitment) {
      txCoinbase.addOutput(Buffer.from(rpcData.default_witness_commitment, 'hex'), 0);
    }
  }

  let header = Buffer.alloc(80);
  { let position = 0;
    header.writeUInt32BE(rpcData.height, position, 4);                  // height         42-46
    header.write(rpcData.bits, position += 4, 4, 'hex');                // bits           47-50
    header.writeUInt32BE(rpcData.curtime, position += 4, 4, 'hex');     // nTime          51-54
    header.write('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD', position += 4, 32, 'hex');                 // merkelRoot     55-87
    header.write(rpcData.previousblockhash, position += 32, 32, 'hex'); // prevblockhash  88-120
    header.writeUInt32BE(rpcData.version, position += 32, 4);           // version        121-153
    header = reverseBuffer(header);
  }
  
  let blob = Buffer.concat([
    header, // 80 bytes
    Buffer.from('AAAAAAAAAAAAAAAA', 'hex'), // 8 bytes
    Buffer.from('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'hex'), // 32 bytes
    varuint.encode(rpcData.transactions.length + 1, Buffer.alloc(varuint.encodingLength(rpcData.transactions.length + 1)), 0)
  ]);
  const offset1 = blob.length; 
  blob = Buffer.concat([ blob, Buffer.from(txCoinbase.toHex(), 'hex') ]);

  rpcData.transactions.forEach(function (value) {
    blob = Buffer.concat([ blob, Buffer.from(value.data, 'hex') ]);
  });

  const EPOCH_LENGTH = 7500;
  const epoch_number = Math.floor(rpcData.height / EPOCH_LENGTH);
  if (last_epoch_number !== epoch_number) {
    let sha3 = new SHA3.SHA3Hash(256);
    if (last_epoch_number && last_epoch_number + 1 === epoch_number) {
      last_seed_hash = sha3.update(last_seed_hash).digest();
    } else {
      last_seed_hash = Buffer.alloc(32, 0);
      for (let i = 0; i < epoch_number; i++) {
        last_seed_hash = sha3.update(last_seed_hash).digest();
        sha3.reset();
      }
    }
    last_epoch_number = epoch_number;
  }

  const difficulty = parseFloat((module.exports.baseRavenDiff() / bignum(rpcData.target, 16).toNumber()).toFixed(9));

  return {
    blocktemplate_blob: blob.toString('hex'),
    // reserved_offset to CCCCCC....
    reserved_offset:    offset1 + 4 /* txCoinbase.version */ + 1 /* vinLen */  + 32 /* hash */ + 4 /* index  */ +
                        1 /* vScript len */ + 1 /* coinbase height len */ + bytesHeight + 1 /* trailing zero byte */,
    seed_hash:          last_seed_hash.toString('hex'),
    difficulty:         difficulty,
    height:             rpcData.height,
    bits:               rpcData.bits,
    prev_hash:          rpcData.previousblockhash,
  };
};

function update_merkle_root_hash(offset, payload, blob_in, blob_out) {
  const nTransactions = varuint.decode(blob_in, offset);
  offset += varuint.decode.bytes;
  let transactions = [];
  for (let i = 0; i < nTransactions; ++i) {
    const tx = bitcoin.Transaction.fromBuffer(blob_in.slice(offset), true, payload && i == 0);
    transactions.push(tx);
    offset += tx.byteLength();
  }
  getMerkleRoot(transactions).copy(blob_out, 4 + 32);
};

module.exports.blockHashBuff = function(blobBuffer) {
  return reverseBuffer(hash256(blobBuffer));
};

module.exports.convertRavenBlob = function(blobBuffer) {
  let header = blobBuffer.slice(0, 80);
  update_merkle_root_hash(80 + 8 + 32, false, blobBuffer, header);
  return module.exports.blockHashBuff(header);
};

module.exports.constructNewRavenBlob = function(blockTemplate, nonceBuff, mixhashBuff) {
  update_merkle_root_hash(80 + 8 + 32, false, blockTemplate, blockTemplate);
  nonceBuff.copy  (blockTemplate, 80, 0, 8);
  mixhashBuff.copy(blockTemplate, 88, 0, 32);
  return blockTemplate;
};

module.exports.constructNewDeroBlob = function(blockTemplate, nonceBuff) {
  nonceBuff.copy(blockTemplate, 39, 0, 4);
  return blockTemplate;
};

module.exports.EthBlockTemplate = function(rpcData) {
  const difficulty = module.exports.baseDiff().div(bignum(rpcData[2].substr(2), 16)).toNumber();
  return {
    hash:               rpcData[0].substr(2),
    seed_hash:          rpcData[1].substr(2),
    difficulty:         difficulty,
    height:             parseInt(rpcData[3])
  };
};

module.exports.ErgBlockTemplate = function(rpcData) {
  const difficulty = module.exports.baseDiff().div(bignum(rpcData.b)).toNumber();
  return {
    hash:               rpcData.msg,
    hash2:              rpcData.pk,
    difficulty:         difficulty,
    height:             parseInt(rpcData.h)
  };
};

module.exports.RtmBlockTemplate = function(rpcData, poolAddress) {
  return rtm.RtmBlockTemplate(rpcData, poolAddress);
};

module.exports.convertRtmBlob = function(blobBuffer) {
  let header = blobBuffer.slice(0, 80);
  update_merkle_root_hash(80, true, blobBuffer, header);
  return header;
};

module.exports.constructNewRtmBlob = function(blockTemplate, nonceBuff) {
  update_merkle_root_hash(80, true, blockTemplate, blockTemplate);
  nonceBuff.copy(blockTemplate, 76, 0, 4);
  return blockTemplate;
};
