#!/usr/bin/env node
import API from "./Api.js";
import { createSecretJWK, createSecretKeyBytes, encrypt } from "./crypto/Encryption.js";
import { entropyToMnemonic, mnemonicToEntropy } from "./crypto/bip39Mnemonic.js";
import { normalizeMnemonic } from "./crypto/mnemonic.js";
import { httpServe } from "./server.js";
import { readFile, writeFile } from "node:fs/promises";

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
tokenized-signing-agent seed <secrets.json> <seed phrase options>
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
tokenized-signing-agent pair <secrets.json> [<seed phrase options>]
    Pair this agent with a user account and optionally configure a seed phrase

<secrets.json> should be a file containing JSON with properties: clientId, clientKey and endpoint
`;

async function accept(configPath, handle) {
    const config = await Config.load(configPath);
    await config.api.registerXPub(await config.api.getSeedPhrase(config.api.rootKeyId), handle);
}

accept.help = `
tokenized-signing-agent accept <secrets.json> <handle>
    Accept an invitation to a workspace to which the signing user has been invited
`;

async function send(configPath, fromHandle, toHandle, instrumentId, amount) {
    const config = await Config.load(configPath);
    let { activity } = await config.api.send(fromHandle, toHandle, instrumentId, amount);
    console.log("Activity:", activity);
}

send.help = `
tokenized-signing-agent send <secrets.json|env:SECRETS> <me@tkz.id> <you@tkz.id> <instrumentID> <amount>
    Send tokens from handle for workspace (which must have been activated already) to handle. 
    instrumentID can be found in the Tokenized desktop app
    amount should be an integer in the minor unit of the token
`;

function help() {
    console.log("Tokenized protocol signing agent");
    console.log(Object.values(commands).map(command => command.help).filter(Boolean).join("\n"));
}


async function serve(configSource, port) {
    const { api } = await Config.load(configSource);
    await httpServe(api, Number(port));
}

serve.help = `
tokenized-signing-agent serve <secrets.json|env:SECRETS> <port>
    Run an HTTP server which can be used to send tokens.
    The HTTP server is unauthenticated and unencrypted and must be run in a secure environment.
`;


const [command, ...args] = process.argv.slice(2);

const commands = { init, pair, seed, send, serve, accept };

try {
    await (commands[command] || help)(...args);
} catch (e) {
    console.error("ERROR:", e);
    process.exit(1);
}