import { Buffer } from 'buffer';
import Hash, { sha256sha256 } from './Hash.js';
import ReadBuffer from './ReadBuffer.js';
import WriteBuffer from './WriteBuffer.js';
import Input from './Input.js';
import Output from './Output.js';
import { arrayBufferToHex, padBytesEnd, numberToBytes } from './utils.js';

// Tx is a Bitcoin transaction.
export default class Tx {
  constructor(serialized) {
    this.version = 1;
    this.inputs = [];
    this.inputSupplements = [];
    this.outputs = [];
    this.outputSupplements = [];
    this.nLockTime = 0;
    this.prevOutsHash = null;
    this.sequenceHash = null;
    this.outputsHash = null;

    if (serialized) {
      if (typeof serialized === 'string' || serialized instanceof String) {
        this.fromString(serialized);
      } else if (serialized instanceof ReadBuffer) {
        this.fromReadBuffer(serialized);
      } else if (Buffer.isBuffer(serialized)) {
        this.fromReadBuffer(new ReadBuffer(serialized));
      } else if (serialized?.constructor?.name === 'ArrayBuffer') {
        this.fromReadBuffer(new ReadBuffer(serialized));
      } else {
        throw new TypeError(
          `Must provide a string or buffer to deserialize a Tx: ${typeof serialized}`,
        );
      }
    }
  }

  // id returns the hash of the serialized transaction data, which is used as the id.
  // If format is specified, then that is used to convert it to a big endian string.
  // Note: Hashes, like txid, are in little endian, but when converted to a string, to display,
  //   it is Bitcoin convention to convert to big endian.
  async id(format) {
    var result = await sha256sha256(this.toBytes());
    if (format == 'hex') {
      return result.toString();
    }
    return result;
  }

  // fromString reads a hex string containing a serialized tx.
  fromString(string) {
    this.fromReadBuffer(new ReadBuffer(string));
  }

  // fromReadBuffer reads a serialized tx from a ReadBuffer.
  fromReadBuffer(buf) {
    this.version = buf.readUInt32LE();

    const sizeTxIns = buf.readVarIntNum();
    for (let i = 0; i < sizeTxIns; i += 1) {
      this.inputs.push(new Input(buf));
    }

    const sizeTxOuts = buf.readVarIntNum();
    for (let i = 0; i < sizeTxOuts; i += 1) {
      this.outputs.push(new Output(buf));
    }

    this.nLockTime = buf.readUInt32LE();

    return this;
  }

  // toString returns a hex string of the serialized tx.
  toString() {
    return arrayBufferToHex(this.toBytes());
  }

  // toBytes returns a Uint8Array containing the tx serialized in binary format.
  toBytes() {
    const writeBuffer = new WriteBuffer();
    this.write(writeBuffer);
    return writeBuffer.toBytes();
  }

  // write writes the tx into a WriteBuffer in binary format.
  write(writeBuffer) {
    writeBuffer.writeUInt32LE(this.version);

    writeBuffer.writeVarIntNum(this.inputs.length);
    for (let i = 0; i < this.inputs.length; i += 1) {
      this.inputs[i].write(writeBuffer);
    }

    writeBuffer.writeVarIntNum(this.outputs.length);
    for (let i = 0; i < this.outputs.length; i += 1) {
      this.outputs[i].write(writeBuffer);
    }

    writeBuffer.writeUInt32LE(this.nLockTime);
  }

  // inputIsSigned returns true if the input at the specified index already has an unlocking
  //   script.
  inputIsSigned(index) {
    return this.inputs[index].script.length > 0;
  }

  // signP2PKHInput creates a P2PKH unlocking script for the specified input.
  async signP2PKHInput(privateKey, inputIndex, lockingScript, value, type) {
    const useType = type || Tx.SIGHASH_ALL | Tx.SIGHASH_FORKID;
    const sighash = await this.sigHash(
      inputIndex,
      lockingScript,
      value,
      useType,
    );
    const sig = await privateKey.sign(sighash);
    const script = new WriteBuffer();

    // Add signature to script.
    // Manually append hash type.
    const sigDER = new WriteBuffer();
    sigDER.write(sig.toBytes());
    sigDER.writeUInt8(useType);

    script.writePushData(sigDER.toBytes());

    // Add public key to script.
    script.writePushData(privateKey.publicKey().toBytes().buffer);

    this.inputs[inputIndex].script = script.toBytes();
  }

  async makePendingTransactionSignature(
    privateKey,
    inputIndex,
    lockingScript,
    value,
    signatureIndex,
    sigHashType,
  ) {
    const useType = sigHashType || Tx.SIGHASH_ALL | Tx.SIGHASH_FORKID;
    const sighash = await this.sigHash(
      inputIndex,
      lockingScript,
      value,
      useType,
    );
    const sig = await privateKey.sign(sighash);
    return {
      input_index: inputIndex,
      signature_index: signatureIndex,
      signature: sig.toString(),
      sig_hash_type: useType,
    };
  }

  // sigHash creates the signature hash for the specified input and the sig hash type.
  async sigHash(inputIndex, lockingScript, value, type) {
    const useType = type || Tx.SIGHASH_ALL | Tx.SIGHASH_FORKID;
    let prevOutsHash;
    if (!(useType & Tx.SIGHASH_ANYONECANPAY)) {
      prevOutsHash = await this.getPrevOutsHash();
    } else {
      prevOutsHash = new Hash(new Uint8Array(32).fill(0)); // Use zero hash
    }

    let sequenceHash;
    if (
      !(useType & Tx.SIGHASH_ANYONECANPAY) &&
      (useType & Tx.SIGHASH_MASK) !== Tx.SIGHASH_SINGLE &&
      (useType & Tx.SIGHASH_MASK) !== Tx.SIGHASH_NONE
    ) {
      sequenceHash = await this.getSequenceHash();
    } else {
      sequenceHash = new Hash(new Uint8Array(32).fill(0)); // Use zero hash
    }

    let outputsHash;
    if (
      (useType & Tx.SIGHASH_MASK) !== Tx.SIGHASH_SINGLE &&
      (useType & Tx.SIGHASH_MASK) !== Tx.SIGHASH_NONE
    ) {
      outputsHash = await this.getOutputsHash();
    } else if (
      (useType & Tx.SIGHASH_MASK) === Tx.SIGHASH_SINGLE &&
      inputIndex < this.outputs.length
    ) {
      outputsHash = await sha256sha256(this.outputs[inputIndex].toBytes());
    } else {
      outputsHash = new Hash(new Uint8Array(32).fill(0)); // Use zero hash
    }

    const buf = new WriteBuffer();

    // Version
    buf.writeUInt32LE(this.version);

    // Outpoints hash
    buf.write(prevOutsHash.toBytes());

    // Sequence hash
    buf.write(sequenceHash.toBytes());

    //  Outpoint
    buf.write(this.inputs[inputIndex].hash.toBytes());
    buf.writeUInt32LE(this.inputs[inputIndex].index);

    // Outpoint locking script
    buf.writeVarIntNum(lockingScript.byteLength);
    buf.write(lockingScript);

    // Outpoint value
    if (value?.constructor?.name === 'ArrayBuffer') {
      buf.write(value);
    } else {
      const b = numberToBytes(value);
      b.reverse();
      const valueBytes = padBytesEnd(b, 8);
      buf.write(valueBytes);
    }

    // Input sequence
    buf.writeUInt32LE(this.inputs[inputIndex].sequence);

    // Outputs
    buf.write(outputsHash.toBytes());

    // Locktime
    buf.writeUInt32LE(this.nLockTime);

    // Hash type
    buf.writeUInt32LE(useType);

    return await sha256sha256(buf.toBytes());
  }

  getFee() {
    if (!this.inputSupplements) {
      throw new Error('No inputSupplements present in Tx');
    }

    const totalInputSatoshis = this.inputSupplements.reduce(
      (acc, is) => acc + BigInt(is?.value || 0) || 0n,
      0n,
    );
    const totalOutputSatoshis = this.outputs.reduce(
      (acc, output) => acc + BigInt(output.value),
      0n,
    );
    const fee = totalInputSatoshis - totalOutputSatoshis;
    return Number(fee);
  }

  async getPrevOutsHash() {
    if (this.prevOutsHash) {
      return this.prevOutsHash;
    }

    const buf = new WriteBuffer();
    for (let i = 0; i < this.inputs.length; i += 1) {
      buf.write(this.inputs[i].hash.toBytes());
      buf.writeUInt32LE(this.inputs[i].index);
    }

    this.prevOutsHash = await sha256sha256(buf.toBytes());
    return this.prevOutsHash;
  }

  async getSequenceHash() {
    if (this.sequenceHash) {
      return this.sequenceHash;
    }

    const buf = new WriteBuffer();
    for (let i = 0; i < this.inputs.length; i += 1) {
      buf.writeUInt32LE(this.inputs[i].sequence);
    }

    this.sequenceHash = await sha256sha256(buf.toBytes());
    return this.sequenceHash;
  }

  async getOutputsHash() {
    if (this.outputsHash) {
      return this.outputsHash;
    }

    const buf = new WriteBuffer();
    for (let i = 0; i < this.outputs.length; i += 1) {
      buf.write(this.outputs[i].toBytes());
    }

    this.outputsHash = await sha256sha256(buf.toBytes());
    return this.outputsHash;
  }

  clearSigHashes() {
    this.prevOutsHash = null;
    this.sequenceHash = null;
    this.outputsHash = null;
  }

  getSpendAmount() {
    const myTotalInputSatoshis = this.inputSupplements.reduce(
      (acc, is) => acc + (is.key_id ? BigInt(is.value) : 0n),
      0n,
    );
    const myTotalChangeSatoshis = this.outputs.reduce((acc, output, i) => {
      const outputSupplement = this.outputSupplements[i];
      if (outputSupplement.key_id) {
        return acc + BigInt(output.value);
      }
      return acc;
    }, 0n);
    const spend = myTotalInputSatoshis - myTotalChangeSatoshis;
    return Number(spend);
  }

  setOutputValue(index, value) {
    this.outputsHash = null;
    this.outputs[index].value = BigInt(value);
  }
}

Tx.SIGHASH_ALL = 0x01;
Tx.SIGHASH_NONE = 0x02;
Tx.SIGHASH_SINGLE = 0x03;
Tx.SIGHASH_FORKID = 0x40;
Tx.SIGHASH_ANYONECANPAY = 0x80;
Tx.SIGHASH_MASK = 0x1f;
