import { Keypair } from "@solana/web3.js";
import _sodium from "libsodium-wrappers-sumo";
import { encode as b58encode, decode as b58decode } from "bs58";

const DEFAULT_HYPERLINK_KEYLENGTH = 12;
const DEFAULT_HASHLESS_HYPERLINK_KEYLENGTH = 16;
const DEFAULT_ORIGIN = "https://hyperlink.org";
export const HYPERLINK_ORIGIN =
    process !== undefined && process.env !== undefined
        ? process.env.HYPERLINK_ORIGIN_OVERRIDE ?? DEFAULT_ORIGIN
        : DEFAULT_ORIGIN;
const HYPERLINK_PATH = "/i";
const VERSION_DELIMITER = "_";

const VALID_VERSIONS = new Set([0, 1, 2]);

const getSodium = async () => {
    await _sodium.ready;
    return _sodium;
};

const kdf = async (
    fullLength: number,
    pwShort: Uint8Array,
    salt: Uint8Array
) => {
    const sodium = await getSodium();
    return sodium.crypto_pwhash(
        fullLength,
        pwShort,
        salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_DEFAULT
    );
};

const randBuf = async (l: number) => {
    const sodium = await getSodium();
    return sodium.randombytes_buf(l);
};

const kdfz = async (fullLength: number, pwShort: Uint8Array) => {
    const sodium = await getSodium();
    const salt = new Uint8Array(sodium.crypto_pwhash_SALTBYTES);
    return await kdf(fullLength, pwShort, salt);
};

const pwToKeypair = async (pw: Uint8Array) => {
    const sodium = await getSodium();
    const seed = await kdfz(sodium.crypto_sign_SEEDBYTES, pw);
    return Keypair.fromSeed(seed);
};

const encryptWithPassword = async (data: Uint8Array, password: string): Promise<Uint8Array> => {
    const sodium = await getSodium();
    const key = await kdfz(sodium.crypto_secretbox_KEYBYTES, new TextEncoder().encode(password));
    const nonce = await randBuf(sodium.crypto_secretbox_NONCEBYTES);
    const encrypted = sodium.crypto_secretbox_easy(data, nonce, key);
    return new Uint8Array([...nonce, ...encrypted]);
};

const decryptWithPassword = async (data: Uint8Array, password: string): Promise<Uint8Array> => {
    const sodium = await getSodium();
    const key = await kdfz(sodium.crypto_secretbox_KEYBYTES, new TextEncoder().encode(password));
    const nonce = data.slice(0, sodium.crypto_secretbox_NONCEBYTES);
    const ciphertext = data.slice(sodium.crypto_secretbox_NONCEBYTES);
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
};

export class HyperLink {
    url: URL;
    keypair: Keypair;

    private constructor(url: URL, keypair: Keypair) {
        this.url = url;
        this.keypair = keypair;
    }

    public static async create(version = 0, password: string): Promise<HyperLink> {
        if (!VALID_VERSIONS.has(version)) {
            throw Error("invalid version");
        }
        await getSodium();
        let b: Uint8Array;
        let keypair: Keypair;
        let hash: string;
        let urlString: string;

        if (version === 2) {
            b = await randBuf(DEFAULT_HASHLESS_HYPERLINK_KEYLENGTH);
            keypair = await pwToKeypair(b);
            const encryptedData = await encryptWithPassword(b, password);
            hash = b58encode(encryptedData);
            urlString = `${HYPERLINK_ORIGIN}${HYPERLINK_PATH}#${VERSION_DELIMITER}2${VERSION_DELIMITER}${hash}`;
        } else if (version === 1) {
            b = await randBuf(DEFAULT_HASHLESS_HYPERLINK_KEYLENGTH);
            keypair = await pwToKeypair(b);
            hash = b58encode(b);
            urlString = `${HYPERLINK_ORIGIN}${HYPERLINK_PATH}#${VERSION_DELIMITER}1${VERSION_DELIMITER}${hash}`;
        } else {
            // version === 0
            b = await randBuf(DEFAULT_HYPERLINK_KEYLENGTH);
            keypair = await pwToKeypair(b);
            hash = b58encode(b);
            urlString = `${HYPERLINK_ORIGIN}${HYPERLINK_PATH}#${hash}`;
        }

        const link = new URL(urlString);
        return new HyperLink(link, keypair);
    }

    public static async fromUrl(url: URL, password?: string): Promise<HyperLink> {
        let slug = url.hash.slice(1);
        let version = 0;
        if (slug.includes(VERSION_DELIMITER)) {
            const parts = slug.split(VERSION_DELIMITER);
            version = Number(parts[1]);
            slug = parts.slice(2).join(VERSION_DELIMITER);
        }
        const encryptedData = Uint8Array.from(b58decode(slug));

        let keypair: Keypair;
        if (version === 2) {
            if (!password) {
                throw new Error("Password is required for version 2 links");
            }
            const decryptedData = await decryptWithPassword(encryptedData, password);
            keypair = await pwToKeypair(decryptedData);
        } else {
            keypair = await pwToKeypair(encryptedData);
        }

        return new HyperLink(url, keypair);
    }

    public static async fromLink(link: string, password?: string): Promise<HyperLink> {
        const url = new URL(link);
        return this.fromUrl(url, password);
    }
}