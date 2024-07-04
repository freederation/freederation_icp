import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface SIGNATURE_INFO {
  'verifying_key' : string,
  'signature_str' : string,
}
export interface _SERVICE {
  'generate_key' : ActorMethod<[], string>,
  'greet' : ActorMethod<[string], string>,
  'rng_seed' : ActorMethod<[], string>,
  'schnorr_signature' : ActorMethod<[string, string], SIGNATURE_INFO>,
  'update_rng_seed' : ActorMethod<[string], undefined>,
  'validate_schnorr' : ActorMethod<[string, string, string], boolean>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
