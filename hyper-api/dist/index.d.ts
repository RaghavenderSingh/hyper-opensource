import { Keypair } from "@solana/web3.js";
export declare const HYPERLINK_ORIGIN: string;
export declare class HyperLink {
    url: URL;
    keypair: Keypair;
    private constructor();
    static create(version: number | undefined, password: string): Promise<HyperLink>;
    static fromUrl(url: URL, password?: string): Promise<HyperLink>;
    static fromLink(link: string, password?: string): Promise<HyperLink>;
}
