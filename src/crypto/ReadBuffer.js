import { Buffer } from 'buffer';
import { hexToArrayBuffer, arrayBufferToHex } from './utils.js';

// ReadBuffer is a Buffer that can be read like a stream.
export default class ReadBuffer {
  constructor(value) {
    this.offset = 0;

    if (value) {
      if (value?.constructor?.name === 'ArrayBuffer') {
        this.buf = value;
      } else if (value instanceof Uint8Array) {
        this.buf = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
      } else if (typeof value === 'string' || value instanceof String) {
        this.buf = hexToArrayBuffer(value);
      } else if (Buffer.isBuffer(value)) {
        this.buf = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
      } else {
        throw new TypeError(
          `ReadBuffer Must provide a Buffer: ${typeof value}`,
        );
      }
      this.view = new DataView(this.buf);
    }
  }

  toString() {
    return arrayBufferToHex(this.buf);
  }

  // read reads the specified number of bytes, returning them in an array buffer.
  read(size) {
    if (this.offset + size > this.buf.byteLength) {
      throw new Error(
        `ReadBuffer not enough data to read: ${this.offset} + ${size} > ${this.buf.byteLength}`,
      );
    }
    const val = this.buf.slice(this.offset, this.offset + size);
    this.offset += size;

    return val;
  }

  // readUInt8 reads an 8 bit unsigned integer.
  readUInt8() {
    const val = this.view.getUint8(this.offset);
    this.offset += 1;
    return val;
  }

  // readUInt16LE reads a 16 bit unsigned integer in little endian format.
  readUInt16LE() {
    const val = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return val;
  }

  // readUInt32LE reads a 32 bit unsigned integer in little endian format.
  readUInt32LE() {
    const val = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return val;
  }

  // readUInt32BE reads a 32 bit unsigned integer in big endian format.
  readUInt32BE() {
    const val = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return val;
  }

  // readVarIntNum reads a Bitcoin P2P encoding variable sized integer.
  readVarIntNum() {
    const first = this.readUInt8();
    switch (first) {
      case 0xfd: // 16 bit integer
        return this.readUInt16LE();
      case 0xfe: // 32 bit integer
        return this.readUInt32LE();
      case 0xff: // 64 bit integer
        return this.read(8);
      default:
        // 8 bit integer
        return first;
    }
  }

  // readPushData reads a Bitcoin script push data, returning it in a buffer.
  // The data is preceded with a variable size that is not included in the returned buffer data.
  // If the next item in the script is not a push data, then the integer value of the next op code
  //   is returned.
  readPushData() {
    const opcode = this.readUInt8();
    if (opcode <= 0x4b) {
      // Max single byte push data size
      return this.read(opcode);
    }
    if (opcode === 0x4c) {
      // OP_PUSH_DATA_1
      const size = this.readUInt8();
      return this.read(size);
    }
    if (opcode === 0x4d) {
      // OP_PUSH_DATA_2
      const size = this.readUInt16LE();
      return this.read(size);
    }
    if (opcode === 0x4e) {
      // OP_PUSH_DATA_4
      const size = this.readUInt32LE();
      return this.read(size);
    }

    // Not a push data. Just return the op code
    return opcode;
  }
}
