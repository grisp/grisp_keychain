-module(grisp_keychain).

-moduledoc """
GRiSP Keychain API

This module provides a common interface for accessing secrets and
identities on GRiSP devices. The actual implementation is delegated
to a configurable backend module (default: `grisp_keychain_filesystem`).

""".

%--- Exports -------------------------------------------------------------------

-export([tls_options/1]).
-export([read_cert/2]).

%--- API Functions -------------------------------------------------------------

-doc """
Get TLS client options for connecting to a specific domain.

Returns a list of SSL/TLS options suitable for use with `ssl:connect/3`
or similar functions. The options include client certificates, trusted
CA certificates, verification settings, and server name indication based
on the application configuration.

## Parameters

- `Domain` - The domain name to connect to. Can be provided as an atom,
  string, binary, or `undefined`. When `undefined`, Server Name
  Indication (SNI) is disabled.

## Returns

A property list of SSL/TLS client options compatible with `ssl:connect/3`.

""".
-spec tls_options(Domain :: atom() | string() | binary() | undefined) ->
    [ssl:tls_client_option()].

tls_options(Domain) ->
    TlsOpts0 = delegate_call(?FUNCTION_NAME, [Domain]),
    case application:get_env(grisp_keychain, allow_expired_certs) of
        {ok, true} -> wrap_verify_option(TlsOpts0, fun allow_expired_certs/3);
        _ -> TlsOpts0
    end.

-doc """
Read a certificate in DER format.

Retrieves the primary client certificate in DER (Distinguished Encoding Rules)
format. This can be useful for certificate inspection or when working with
external cryptographic libraries.

## Parameters

- `CertType` - Currently only `primary` is supported, which refers to the
  main client certificate.
- `Format` - Currently only `der` is supported, which returns the certificate
  in DER binary format.

## Returns

The certificate as a binary in DER format.
""".
-spec read_cert(CertType :: primary, Format :: der) -> binary().

read_cert(primary, der) ->
    delegate_call(?FUNCTION_NAME, [primary, der]).

%--- Internal Functions --------------------------------------------------------

-doc false.
-dialyzer({nowarn_function, delegate_call/2}).
-spec delegate_call(Function :: atom(), Args :: [term()]) -> term().

delegate_call(Function, Args) ->
    {ok, Module} = application:get_env(grisp_keychain, api_module),
    erlang:apply(Module, Function, Args).

%--- TLS verify chaining -------------------------------------------------------

-doc false.
wrap_verify_option(Opts0, Fun) when is_function(Fun, 3) ->
    Existing =
        case lists:keyfind(verify_fun, 1, Opts0) of
            {verify_fun, {Fun, State}} when is_function(Fun, 3) ->
                {Fun, State};
            {verify_fun, Fun} when is_function(Fun, 3) ->
                {Fun, undefined};
            _ ->
                undefined
        end,
    Opts1 = lists:keydelete(verify_fun, 1, Opts0),
    [{verify_fun, {Fun, Existing}} | Opts1].

-doc false.
allow_expired_certs(_Cert, {bad_cert, cert_expired}, User) ->
    {valid, User};
allow_expired_certs(Cert, Event, {UserFun, UserState}) ->
    case UserFun(Cert, Event, UserState) of
        {valid, NewState} -> {valid, {UserFun, NewState}};
        {valid_peer, NewState} -> {valid_peer, {UserFun, NewState}};
        {unknown, NewState} -> {unknown, {UserFun, NewState}};
        {fail, Reason} -> {fail, Reason}
    end;
allow_expired_certs(_Cert, valid, State) ->
    {valid, State};
allow_expired_certs(_Cert, valid_peer, State) ->
    {valid_peer, State};
allow_expired_certs(_Cert, {extension, _}, State) ->
    {unknown, State};
allow_expired_certs(_Cert, {bad_cert, Reason}, _State) ->
    {fail, Reason}.
