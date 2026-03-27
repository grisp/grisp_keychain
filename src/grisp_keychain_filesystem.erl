-module(grisp_keychain_filesystem).

-moduledoc """
Filesystem `api_module` for grisp_keychain

Implements the keychain API for direct filesystem based access to certificates and keys.
""".

%--- Exports -------------------------------------------------------------------

% API functions
-export([tls_options/1]).
-export([read_cert/2]).

% Utility functions
-export([load_key/1]).
-export([load_certs/1]).


%--- API Functions -------------------------------------------------------------

-spec tls_options(DomainName :: atom() | string() | binary() |  undefined)
    -> [ssl:tls_client_option()].

tls_options(DomainName) ->
    {CertsKeys, ClientTrustedCerts} =
        case grisp_keychain_utils:use_client_certificate() of
            false -> {[], []};
            true ->
                ClientCerts = client_certs(),
                ClientKey = client_key(),
                TrustedCerts = grisp_keychain_utils:client_trusted_certs(),
                {certs_keys_config(ClientCerts, ClientKey), TrustedCerts}
        end,
    grisp_keychain_utils:build_tls_options(DomainName, CertsKeys, ClientTrustedCerts).

read_cert(primary, der) ->
    [PemBin|_] = client_certs(),
    PemBin.

%--- Internal Functions --------------------------------------------------------

client_certs() ->
    case grisp_keychain_utils:get_config_path(client_certs) of
        undefined -> throw(no_client_certificates);
        {ok, Path} -> grisp_keychain_utils:load_certs(Path)
    end.


client_key() ->
    case grisp_keychain_utils:get_config_path(client_key) of
        undefined -> throw(no_client_key);
        {ok, Path} -> grisp_keychain_utils:load_key(Path)
    end.

certs_keys_config(ClientCerts, ClientKey) ->
    [{certs_keys, [#{
        cert => ClientCerts,
        key => ClientKey
    }]}].

load_key(FilePath) ->
    grisp_keychain_utils:load_key(FilePath).

load_certs(FilePath) ->
    grisp_keychain_utils:load_certs(FilePath).
