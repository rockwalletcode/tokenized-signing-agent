#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import API from "./Api.js";
import { createSecretJWK, createSecretKeyBytes, encrypt } from "./crypto/Encryption.js";
import { entropyToMnemonic, mnemonicToEntropy } from "./crypto/bip39Mnemonic.js";
import { normalizeMnemonic } from "./crypto/mnemonic.js";
import { httpServe, httpHelp } from "./server.js";
const { styleText = (_, content) => content } = await import("node:util");

let version;
try {
    version = JSON.parse(await readFile(new URL("../package.json", import.meta.url))).version;
} catch (e) { }

const commandStyle = content => `tokenized-signing-agent ${styleText('bold', styleText('red', content))}`;

class Config {
    constructor(configPath, settings) {
        this.configPath = configPath;
        this.settings = settings;
        this.api = new API(settings);
    }

    update(settings) {
        this.settings = { ...this.settings, ...settings };
    }

    async save() {
        if (!this.configPath) {
            throw "No configuration file to write";
        }
        await writeFile(this.configPath, JSON.stringify(this.settings, null, 4), { encoding: "utf8" });
    }

    static async load(configSource) {
        if (!configSource) throw "No configuration supplied";
        let configText, configPath;
        if (configSource.startsWith("env:")) {
            configText = process.env[configSource.slice("env:".length)];
        } else {
            configText = await readFile(configSource, { encoding: "utf8" })
            configPath = configSource;
        }
        return new Config(configPath, JSON.parse(configText));
    }
}


async function init(configPath, endpoint) {
    const config = new Config(configPath, { endpoint });
    await config.save();
}

/** @param {Config} config */
async function configureSeedPhrase(config, seedPhraseOptions) {

    const encryptionSecret = await createSecretJWK();
    let entropy;
    let rootKeyId;
    let seedPhrase;

    let create = seedPhraseOptions == ":generate" || seedPhraseOptions == ":silent";
    if (create) {
        if (await config.api.hasRootkeys()) {
            throw "Account already has root keys. Supply a seed phrase.";
        }
        entropy = await createSecretKeyBytes();
        seedPhrase = await entropyToMnemonic(entropy);
        if (seedPhraseOptions != ":silent") {
            console.log("Seed phrase:");
            console.log(seedPhrase);
        }
    } else {
        seedPhrase = normalizeMnemonic(await readFile(seedPhraseOptions, { encoding: "utf8" }));
        entropy = await mnemonicToEntropy(seedPhrase);
        rootKeyId = await config.api.verifySeedPhrase(seedPhrase);
    }
    const encryptedEntropy = await encrypt(entropy, encryptionSecret);

    rootKeyId = await config.api.storeEncryptedRootKey(encryptedEntropy, rootKeyId);
    if (create) {
        const handle = await config.api.registerXPub(seedPhrase);
        console.log("Handle", handle);
    }
    config.update({ rootKeyId, encryptionSecret });
    await config.save();
}

async function seed(configPath, seedPhrase) {
    const config = await Config.load(configPath);
    if (config.settings.encryptionSecret) throw "Seedphrase already configured";

    await configureSeedPhrase(config, seedPhrase);
}

seed.help = `
${commandStyle('seed')} <secrets.json> <seed phrase options>
    Configure a seed phrase for signing

<seed phrase options>
:generate
    Generate and print a seed phrase
:silent
    Generate and do not print a seed phrase
<seed-phrase-file>
    Use an existing (previously paired for this account) seed phrase
`;

async function pair(configPath, pairingCode, seedPhraseOptions) {
    const config = await Config.load(configPath);
    if (config.settings.privateJWK) throw "Already paired";

    config.update(await config.api.pair(pairingCode));
    await config.save();
    if (seedPhraseOptions) {
        await configureSeedPhrase(config, seedPhraseOptions);
    }
}

pair.help = `
${commandStyle('pair')} <secrets.json> <pairing code> [<seed phrase options>]
    Pair this agent with a user account and optionally configure a seed phrase

<secrets.json> should be a file containing JSON with properties: clientId, clientKey and endpoint
`;

async function accept(configPath, handle) {
    const config = await Config.load(configPath);
    await config.api.registerXPub(await config.api.getSeedPhrase(config.api.rootKeyId), handle);
}

accept.help = `
${commandStyle('accept')} <secrets.json> <handle>
    Accept an invitation to a workspace to which the signing user has been invited
`;

async function send(configPath, fromHandle, toHandle, instrumentId, amount) {
    const config = await Config.load(configPath);
    let { activity, txs, executed } = await config.api.send(fromHandle, toHandle, instrumentId, amount);
    console.log("Activity ID:", activity);
    if (executed) {
        console.log("Tx ids:", txs);
    } else {
        console.log("Execution in progress");
    }
}

send.help = `
${commandStyle('send')} <secrets.json|env:SECRETS> <me@tkz.id> <you@tkz.id> <instrumentID> <amount>
    Send tokens from handle for workspace (which must have been activated already) to handle. 
    instrumentID can be found in the Tokenized desktop app
    amount should be an integer in the minor unit of the token
`;

async function describe(configPath, handle, activityId) {
    const config = await Config.load(configPath);
    console.log(await config.api.describe(handle, activityId));
}

describe.help = `
${commandStyle('describe')} <secrets.json|env:SECRETS> <me@tkz.id> <activity ID>
    Provide details about a previous transfer.
    Note the output of this command is not expected to remain stable and may change.
    Contact support for more information.
`;


function help() {
    console.log("Tokenized protocol signing agent");
    if (version) console.log("Version", styleText("bold", version));
    console.log(Object.values(commands).map(command => command.help).filter(Boolean).join("\n"));
}


async function serve(configSource, port) {
    const { api } = await Config.load(configSource);
    await httpServe(api, Number(port));
}

serve.help = `
${commandStyle('serve')} <secrets.json|env:SECRETS> <port>
    Run an HTTP server which can be used to send tokens.
    The HTTP server is unauthenticated and unencrypted and must be run in a secure environment.
${httpHelp}
`;

async function show(configSource) {
    const config = await Config.load(configSource);
    console.log(await config.api.getSeedPhrase(config.api.rootKeyId));
}

show.help = `
${commandStyle('show')} <secrets.json|env:SECRETS>
    Print seed phrase
`;

const [command, ...args] = process.argv.slice(2);

const commands = { init, pair, seed, send, serve, accept, show, describe };

try {
    await (commands[command] || help)(...args);
} catch (e) {
    console.error("ERROR:", e);
    process.exit(1);
}