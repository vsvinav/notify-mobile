/* tslint:disable */
/* eslint-disable */

export class Message {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    bytes(): Uint8Array;
    sender(): Uint8Array;
}

export class Peer {
    free(): void;
    [Symbol.dispose](): void;
    add_pinned(bytes: Uint8Array | number[], expected: Uint8Array | number[]): Uint8Array;
    create(id: string): void;
    export_identity(): Uint8Array;
    identity_key(): Uint8Array;
    join_pinned(welcome: Uint8Array | number[], tree: Uint8Array | number[], expected: Uint8Array | number[]): void;
    key_package(): Uint8Array;
    constructor(label: string);
    receive(bytes: Uint8Array | number[]): Message;
    static restore_identity(label: string, bytes: Uint8Array | number[], expected: Uint8Array | number[]): Peer;
    send(plaintext: Uint8Array | number[]): Uint8Array;
    sign_authorization(challenge: Uint8Array | number[]): Uint8Array;
    tree(): Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_message_free: (a: number, b: number) => void;
    readonly __wbg_peer_free: (a: number, b: number) => void;
    readonly message_bytes: (a: number) => [number, number];
    readonly message_sender: (a: number) => [number, number];
    readonly peer_add_pinned: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly peer_create: (a: number, b: number, c: number) => [number, number];
    readonly peer_export_identity: (a: number) => [number, number, number, number];
    readonly peer_identity_key: (a: number) => [number, number];
    readonly peer_join_pinned: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly peer_key_package: (a: number) => [number, number, number, number];
    readonly peer_new: (a: number, b: number) => [number, number, number];
    readonly peer_receive: (a: number, b: number, c: number) => [number, number, number];
    readonly peer_restore_identity: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly peer_send: (a: number, b: number, c: number) => [number, number, number, number];
    readonly peer_sign_authorization: (a: number, b: number, c: number) => [number, number, number, number];
    readonly peer_tree: (a: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
