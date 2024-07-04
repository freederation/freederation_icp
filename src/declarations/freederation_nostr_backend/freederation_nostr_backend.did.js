export const idlFactory = ({ IDL }) => {
  const SIGNATURE_INFO = IDL.Record({
    'verifying_key' : IDL.Text,
    'signature_str' : IDL.Text,
  });
  return IDL.Service({
    'generate_key' : IDL.Func([], [IDL.Text], ['query']),
    'greet' : IDL.Func([IDL.Text], [IDL.Text], ['query']),
    'rng_seed' : IDL.Func([], [IDL.Text], ['query']),
    'schnorr_signature' : IDL.Func(
        [IDL.Text, IDL.Text],
        [SIGNATURE_INFO],
        ['query'],
      ),
    'update_rng_seed' : IDL.Func([IDL.Text], [], []),
    'validate_schnorr' : IDL.Func(
        [IDL.Text, IDL.Text, IDL.Text],
        [IDL.Bool],
        ['query'],
      ),
  });
};
export const init = ({ IDL }) => { return []; };
