import XKey from "./crypto/XKey.js";
import { generateECDSAJWK, importPrivateKey } from "./jwk.js";
import { createJWT, expiredFraction } from "./jwt.js";
import { mnemonic2Seed } from "./crypto/mnemonic.js";
import Tx from "./crypto/Tx.js";
import { decrypt } from "./crypto/Encryption.js";
import { hexToArrayBuffer } from "./crypto/utils.js";
import { entropyToMnemonic } from "./crypto/bip39Mnemonic.js";

function url([first, ...strings], ...parameters) {
  return (
    first +
    parameters
      .map((key, index) => encodeURIComponent(key) + strings[index])
      .join('')
  );
}

export default class API {
  constructor({ clientId, clientKey, keyId, privateJWK, endpoint, deviceId, encryptionSecret, rootKeyId }) {
    this.clientId = clientId;
    this.clientKey = clientKey;
    this.keyId = keyId;
    this.privateJWK = privateJWK;
    this.endpoint = endpoint;
    this.deviceId = deviceId;
    this.encryptionSecret = encryptionSecret;
    this.rootKeyId = rootKeyId;
  }

  async updateDeviceAuthToken() {
    if (!this.privateJWK) throw "Pairing not found";
    const privateKey = await importPrivateKey(this.privateJWK);

    let singleUseJWT = await createJWT(this.keyId, privateKey, {
      jti: `${Date.now()}`,
    });

    const { data: { token } } = await this.fetch("GET", url`auth/token/device`, null, singleUseJWT);

    this.tokenCreatedAt = Date.now() / 1e3;
    this.jwt = token;
    this.updateTokenPromise = null;
  }

  async pair(pairingCode) {
    const { keyId, privateJWK, publicJWK } = await generateECDSAJWK();

    const { data: { id: deviceId } } = await this.fetch(
      "POST",
      url`users/@me/devices/code`,
      {
        pairing_code: pairingCode,
        client_key: this.clientKey,
        client_id: this.clientId,
        external_id: this.clientId,
        public_key: JSON.stringify(publicJWK),
        key_id: keyId,
        is_active: true,
        provider_name: `signing-agent-1`,
        manufacturer_name: '',
        device_name: 'Pairing',
        provider_id: 'File:-',
      },
      false,
    );

    this.privateJWK = privateJWK;
    this.keyId = keyId;
    this.deviceId = deviceId;

    return { privateJWK, keyId, deviceId };
  }

  static async makeXPub(seedPhrase, path) {
    const rootKey = await XKey.fromSeed(await mnemonic2Seed(seedPhrase))
    const xKey = await rootKey.derive(path);
    return xKey.toPublic().toString();
  }

  static async makeXPubInternal(seedPhrase, path) {
    const rootKey = await XKey.fromSeed(await mnemonic2Seed(seedPhrase))
    const xKey = await rootKey.derive(path);
    return Buffer.from(xKey.toPublic().toInternalBytes()).toString("hex");
  }

  async verifySeedPhrase(seedPhrase) {
    const { data: rootKeys } = await this.fetch("GET", url`users/@me/rootkeys`);
    if (!rootKeys.length) return null;

    for (let { id: rootKeyId } of rootKeys) {
      const { data: { derivation_path } } = await this.fetch("GET", url`users/@me/rootkeys/${rootKeyId}/check`);
      const xpub = await API.makeXPub(seedPhrase, derivation_path);
      await this.fetch("POST", url`users/@me/rootkeys/${rootKeyId}/check`, { derivation_path, xpub });
      return rootKeyId;
    }
    throw new Error("Seed phrase is not valid");
  }

  async registerXPub(seedPhrase, handle = null) {
    const { data: proposals } = await this.fetch("GET", url`proposals`);

    const personalProfile = proposals.find(proposal => proposal.invited_profile_id);
    const proposal = proposals.find(proposal => handle ? proposal.handle == handle : proposal.id == personalProfile.id);

    if (!proposal?.lockbox_id) throw "Invitation not found for handle";

    const lockboxId = proposal.lockbox_id;
    const profileId = personalProfile.invited_profile_id;

    const { data: { path } } = await this.fetch(
      "GET",
      url`profiles/${profileId}/lock_boxes/${lockboxId}/rootkeys/${this.rootKeyId}/proposal`
    );
    const xpub = await this.makeXPub(seedPhrase, path);
    await this.fetch(
      "POST",
      url`profiles/${profileId}/lock_boxes/${lockboxId}/rootkeys/${this.rootKeyId}/proposal`,
      { path, xpub }
    );

    return proposal.handle;
  }

  async storeEncryptedRootKey(encryptedEntropy, rootKeyId) {
    const body = {
      id: rootKeyId,
      encrypted: encryptedEntropy.toString('hex'),
      device_id: this.deviceId,
    };
    try {
      const { data: { id } } = await this.fetch("POST", url`users/@me/rootkeys`, body);
      this.rootKeyId = id;
      return id;
    } catch (e) {
      if (e.status == "409") throw "Root key already registered";
      throw e;
    }
  }

  async hasRootkeys() {
    const { data: rootkeys } = await this.fetch("GET", url`users/@me/rootkeys`);
    return !!rootkeys.length;
  }

  async getEncryptedRootKey(rootKeyId) {
    const { data: rootkeys } = await this.fetch("GET", url`users/@me/rootkeys`);
    return Buffer.from(rootkeys.find(({ id, device_id }) => (!rootKeyId || id == rootKeyId) && device_id == this.deviceId)?.encrypted, "hex");
  }

  async send(fromHandle, toHandle, instrument, amount) {
    const { data: proposals } = await this.fetch("GET", url`proposals`);

    const proposal = proposals.find(proposal => proposal.handle == fromHandle);

    if (!proposal?.is_accepted) throw "Handle not yet activated";

    const profileId = proposal.profile_id;

    const body = {
      lock_box_id: proposal.lockbox_id,
      recipients: [{ handle: toHandle, amount: Number(amount) }],
      instrument
    };
    const { data: { activity_id } } = await this.fetch("PUT", url`profiles/${profileId}/send`, body);

    while (true) {
      const { data: { transactions } } = await this.fetch("GET", url`profiles/${profileId}/activity/${activity_id}`);

      let pending = transactions.filter(({ type }) => type == "pending_tx");

      if (!pending.length) {
        console.log("Waiting for pending transactions to sign");
        await new Promise(resolve => setTimeout(resolve, 250));
        continue;
      }

      const { pending_transaction_id } = pending[0];

      await this.signPendingTxId(profileId, pending_transaction_id);
      break;
    }

    let patience = 20;
    while (patience-- > 0) {
      const { data: { stage, transactions } } = await this.fetch("GET", url`profiles/${profileId}/activity/${activity_id}`);

      if (stage != "executed") {
        console.log("Waiting for completion");
        await new Promise(resolve => setTimeout(resolve, 250));
        continue;
      }

      let txs = transactions.filter(({ type }) => type == "tx").map(({ txid }) => txid);

      return { activity: activity_id, txs, executed: true };
    }
    return { activity: activity_id, executed: false };
  }

  async describe(handle, activity_id) {
    const { data: proposals } = await this.fetch("GET", url`proposals`);

    const proposal = proposals.find(proposal => proposal.handle == handle);
    const profileId = proposal.profile_id;

    const { data } = await this.fetch("GET", url`profiles/${profileId}/activity/${activity_id}`);
    return data;
  }



  async getSeedPhrase(rootKeyId) {
    const encryptedEntropy = await this.getEncryptedRootKey(rootKeyId);
    const decryptedEntropy = await decrypt(encryptedEntropy, this.encryptionSecret);
    return await entropyToMnemonic(decryptedEntropy);
  }

  async sign(profileId, pendingTransaction) {
    const tx = new Tx(pendingTransaction.tx);
    const signatures = [];
    for (let [index, input] of pendingTransaction.input_supplements.entries()) {
      const lockingScriptBuf = hexToArrayBuffer(input.locking_script);

      for (let needed of input.needed_signatures) {
        const seedPhrase = await this.getSeedPhrase(needed.root_key_id);
        const mnemonicSeed = await mnemonic2Seed(seedPhrase);
        const rootXKey = await XKey.fromSeed(mnemonicSeed);

        const childKey = await rootXKey.derive(needed.derivation_path);
        signatures.push(await tx.makePendingTransactionSignature(
          childKey.key(),
          index,
          lockingScriptBuf,
          input.value,
          needed.signature_index,
          needed.sig_hash_type,
        ));
      }
    }

    const response = await this.fetch(
      "POST",
      url`profiles/${profileId}/pending_transactions/${pendingTransaction.id}`,
      { signatures }
    );

    let txId = await tx.id("hex");

    if (response?.data) {
      return [txId, ...await this.sign(profileId, response?.data)];
    }

    return [txId];
  }

  async signPendingTxId(profileId, pendingTransactionId) {
    const response = await this.fetch(
      "GET", url`profiles/${profileId}/pending_transactions/${pendingTransactionId}`
    );

    return await this.sign(profileId, response.data);
  }

  async getToken() {
    if (!this.jwt || expiredFraction(this.jwt, this.tokenCreatedAt) > 0.5) {
      await (this.updateTokenPromise ||= await this.updateDeviceAuthToken());
    }
    return this.jwt;
  }

  async fetch(method, urlSuffix, body, token) {
    if (token === undefined) {
      token = await this.getToken();
    }

    let response = await fetch(
      new URL(urlSuffix, this.endpoint),
      {
        method,
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: body ? JSON.stringify(body) : undefined
      }
    );

    if (!response.ok) {
      const error = new Error(`API Error: ${response.status}`);
      error.content = await response.text();
      error.status = response.status;
      throw error;
    }

    return response.headers.get("Content-type") ? await response.json() : await response.text();
  }
}
