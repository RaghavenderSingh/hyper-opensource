"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.HyperLink = exports.HYPERLINK_ORIGIN = void 0;
const web3_js_1 = require("@solana/web3.js");
const libsodium_wrappers_sumo_1 = __importDefault(require("libsodium-wrappers-sumo"));
const bs58_1 = require("bs58");
const DEFAULT_HYPERLINK_KEYLENGTH = 12;
const DEFAULT_HASHLESS_HYPERLINK_KEYLENGTH = 16;
const DEFAULT_ORIGIN = "https://hyperlink.org";
exports.HYPERLINK_ORIGIN = process !== undefined && process.env !== undefined
    ? (_a = process.env.HYPERLINK_ORIGIN_OVERRIDE) !== null && _a !== void 0 ? _a : DEFAULT_ORIGIN
    : DEFAULT_ORIGIN;
const HYPERLINK_PATH = "/i";
const VERSION_DELIMITER = "_";
const VALID_VERSIONS = new Set([0, 1, 2]);
const getSodium = () => __awaiter(void 0, void 0, void 0, function* () {
    yield libsodium_wrappers_sumo_1.default.ready;
    return libsodium_wrappers_sumo_1.default;
});
const kdf = (fullLength, pwShort, salt) => __awaiter(void 0, void 0, void 0, function* () {
    const sodium = yield getSodium();
    return sodium.crypto_pwhash(fullLength, pwShort, salt, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE, sodium.crypto_pwhash_ALG_DEFAULT);
});
const randBuf = (l) => __awaiter(void 0, void 0, void 0, function* () {
    const sodium = yield getSodium();
    return sodium.randombytes_buf(l);
});
const kdfz = (fullLength, pwShort) => __awaiter(void 0, void 0, void 0, function* () {
    const sodium = yield getSodium();
    const salt = new Uint8Array(sodium.crypto_pwhash_SALTBYTES);
    return yield kdf(fullLength, pwShort, salt);
});
const pwToKeypair = (pw) => __awaiter(void 0, void 0, void 0, function* () {
    const sodium = yield getSodium();
    const seed = yield kdfz(sodium.crypto_sign_SEEDBYTES, pw);
    return web3_js_1.Keypair.fromSeed(seed);
});
const encryptWithPassword = (data, password) => __awaiter(void 0, void 0, void 0, function* () {
    const sodium = yield getSodium();
    const key = yield kdfz(sodium.crypto_secretbox_KEYBYTES, new TextEncoder().encode(password));
    const nonce = yield randBuf(sodium.crypto_secretbox_NONCEBYTES);
    const encrypted = sodium.crypto_secretbox_easy(data, nonce, key);
    return new Uint8Array([...nonce, ...encrypted]);
});
const decryptWithPassword = (data, password) => __awaiter(void 0, void 0, void 0, function* () {
    const sodium = yield getSodium();
    const key = yield kdfz(sodium.crypto_secretbox_KEYBYTES, new TextEncoder().encode(password));
    const nonce = data.slice(0, sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = data.slice(sodium.crypto_secretbox_NONCEBYTES);
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
});
class HyperLink {
    constructor(url, keypair) {
        this.url = url;
        this.keypair = keypair;
    }
    static create(version = 0, password) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!VALID_VERSIONS.has(version)) {
                throw Error("invalid version");
            }
            yield getSodium();
            let b;
            let keypair;
            let hash;
            let urlString;
            if (version === 2) {
                b = yield randBuf(DEFAULT_HASHLESS_HYPERLINK_KEYLENGTH);
                keypair = yield pwToKeypair(b);
                const encryptedData = yield encryptWithPassword(b, password);
                hash = (0, bs58_1.encode)(encryptedData);
                urlString = `${exports.HYPERLINK_ORIGIN}${HYPERLINK_PATH}#${VERSION_DELIMITER}2${VERSION_DELIMITER}${hash}`;
            }
            else if (version === 1) {
                b = yield randBuf(DEFAULT_HASHLESS_HYPERLINK_KEYLENGTH);
                keypair = yield pwToKeypair(b);
                hash = (0, bs58_1.encode)(b);
                urlString = `${exports.HYPERLINK_ORIGIN}${HYPERLINK_PATH}#${VERSION_DELIMITER}1${VERSION_DELIMITER}${hash}`;
            }
            else {
                // version === 0
                b = yield randBuf(DEFAULT_HYPERLINK_KEYLENGTH);
                keypair = yield pwToKeypair(b);
                hash = (0, bs58_1.encode)(b);
                urlString = `${exports.HYPERLINK_ORIGIN}${HYPERLINK_PATH}#${hash}`;
            }
            const link = new URL(urlString);
            return new HyperLink(link, keypair);
        });
    }
    static fromUrl(url, password) {
        return __awaiter(this, void 0, void 0, function* () {
            let slug = url.hash.slice(1);
            let version = 0;
            if (slug.includes(VERSION_DELIMITER)) {
                const parts = slug.split(VERSION_DELIMITER);
                version = Number(parts[1]);
                slug = parts.slice(2).join(VERSION_DELIMITER);
            }
            const encryptedData = Uint8Array.from((0, bs58_1.decode)(slug));
            let keypair;
            if (version === 2) {
                if (!password) {
                    throw new Error("Password is required for version 2 links");
                }
                const decryptedData = yield decryptWithPassword(encryptedData, password);
                keypair = yield pwToKeypair(decryptedData);
            }
            else {
                keypair = yield pwToKeypair(encryptedData);
            }
            return new HyperLink(url, keypair);
        });
    }
    static fromLink(link, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const url = new URL(link);
            return this.fromUrl(url, password);
        });
    }
}
exports.HyperLink = HyperLink;
