import wordList from './bip39WordList.js';

// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
// Only implemented for 256 bit entropy

export async function entropyToMnemonic(entropy) {
  if (!entropy) return;
  const checksum = await crypto.subtle.digest('SHA-256', entropy);
  const entropyBuffer = Buffer.from(entropy);
  const mnemonicData = Buffer.concat([entropyBuffer, Buffer.from(checksum)]);

  let bits = entropyBuffer.length * 8 + entropyBuffer.length / 4;

  const words = [];

  while (bits > 0) {
    const wordIndex = (mnemonicData[0] << 3) + (mnemonicData[1] >> 5);
    words.push(wordList[wordIndex]);
    bits -= 11;

    for (let i = 0; i < (bits + 7) >> 3; i++) {
      mnemonicData[i] = (mnemonicData[i + 1] << 3) + (mnemonicData[i + 2] >> 5);
    }
  }

  return words.join(' ');
}

export async function mnemonicToEntropy(mnemonic) {
  let words = mnemonic.split(/\s+/);

  let mnemonicData = Buffer.alloc((words.length * 11) / 8);

  let bitLength = 0;
  let bits = 0;
  let byteIndex = 0;

  for (let word of words) {
    let wordIndex = wordList.indexOf(word);
    if (wordIndex < 0) {
      throw new Error(`Unknown word: ${word}`)
    }
    bits = (bits << 11) + wordIndex;

    bitLength += 11;
    while (bitLength >= 8) {
      bitLength -= 8;
      mnemonicData[byteIndex++] = (bits >>> bitLength) & 0xff;
    }
  }

  const entropy = mnemonicData.subarray(0, 32);

  const checksum = await crypto.subtle.digest('SHA-256', entropy);

  if (mnemonicData[32] != Buffer.from(checksum)[0]) {
    throw new Error('Mnemonic checksum failed');
  }

  return entropy;
}
