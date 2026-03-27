-module(grisp_keychain_utils).

-moduledoc """
Shared TLS configuration and certificate-loading helpers for `grisp_keychain`
backends.
""".

-export([build_tls_options/3]).
-export([use_client_certificate/0]).
-export([client_trusted_certs/0]).
-export([server_trusted_certs/1]).
-export([system_ca_certs/0]).
-export([get_config/1]).
-export([get_config_path/1]).
-export([get_config_path/2]).
-export([get_config_cb/2]).
-export([resolve_path/1]).
-export([load_key/1]).
-export([load_certs/1]).


%--- External API Functions ----------------------------------------------------

-spec build_tls_options(
    DomainName :: atom() | string() | binary() | undefined,
    CertsKeys :: [ssl:tls_client_option()],
    ClientTrustedCerts :: [public_key:der_encoded()]
) -> [ssl:tls_client_option()].
build_tls_options(DomainName, CertsKeys, ClientTrustedCerts) ->
    DomainNameStr = domain_name(DomainName),
    ServerNameIndication = server_name_indication(DomainNameStr),
    case tls_verify() of
        verify_none ->
            [{verify, verify_none},
             {server_name_indication, ServerNameIndication},
             {cacerts, ClientTrustedCerts}
             | CertsKeys];
        verify_peer ->
            ServerTrustedCerts = server_trusted_certs(DomainNameStr),
            [{verify, verify_peer},
             {depth, 99},
             {cacerts, ClientTrustedCerts ++ ServerTrustedCerts},
             {server_name_indication, ServerNameIndication},
             {customize_hostname_check, [
                {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
             ]}
             | CertsKeys]
    end.

use_client_certificate() ->
    case get_config(tls_use_client_certificate) of
        undefined -> true;
        {ok, Flag} when is_boolean(Flag) -> Flag
    end.

client_trusted_certs() ->
    tls_client_trusted_certs() ++ tls_client_trusted_certs_cb().

server_trusted_certs(undefined) ->
    tls_server_trusted_certs_cb();
server_trusted_certs(DomainName) ->
    tls_server_trusted_certs(DomainName) ++ tls_server_trusted_certs_cb().

system_ca_certs() ->
    try load_certs("/etc/ssl/certs/ca-certificates.crt")
    catch throw:_Reason -> []
    end.

get_config(Key) ->
    application:get_env(grisp_keychain, Key).

get_config_path(Key) ->
    case get_config(Key) of
        undefined -> undefined;
        {ok, PathSpec} -> {ok, resolve_path(PathSpec)}
    end.

get_config_path(Key, DefaultPathSpec) ->
    case get_config(Key) of
        undefined -> resolve_path(DefaultPathSpec);
        {ok, PathSpec} -> resolve_path(PathSpec)
    end.

get_config_cb(Key, Default) ->
    case application:get_env(grisp_keychain, Key) of
        undefined -> Default;
        {ok, undefined} -> Default;
        {ok, {ModName, FunName}}
          when is_atom(ModName), is_atom(FunName) ->
            ModName:FunName();
        {ok, {ModName, FunName, FunArgs}}
          when is_atom(ModName), is_atom(FunName) ->
            erlang:apply(ModName, FunName, FunArgs)
    end.

resolve_path(undefined) -> undefined;
resolve_path(AbsPath) when is_list(AbsPath) -> AbsPath;
resolve_path(AbsPath) when is_binary(AbsPath) ->
    unicode:characters_to_list(AbsPath);
resolve_path({Tag, AppName, RelPath})
  when is_atom(Tag), is_atom(AppName), is_binary(RelPath) ->
    resolve_path({Tag, AppName, unicode:characters_to_list(RelPath)});
resolve_path({priv, AppName, RelPath})
  when is_atom(AppName), is_list(RelPath) ->
    case code:priv_dir(AppName) of
        {error, bad_name} -> throw({bad_appname, AppName});
        BasePath -> filename:join(BasePath, RelPath)
    end;
resolve_path({test, AppName, RelPath})
  when is_atom(AppName), is_list(RelPath) ->
    case code:lib_dir(AppName) of
        {error, bad_name} -> throw({bad_appname, AppName});
        BasePath ->
            TestDir = locate_test_dir(BasePath),
            filename:join(TestDir, RelPath)
    end.

load_key(FilePath) ->
    case file:read_file(FilePath) of
        {error, enoent} ->
            throw({file_not_found, FilePath});
        {ok, PemData} ->
            case public_key:pem_decode(PemData) of
                [] ->
                    throw({invalid_key, FilePath});
                [{Asn1Type, DerData, not_encrypted}] ->
                    {Asn1Type, DerData};
                [{_Asn1Type, _DerData, _}] ->
                    throw(encrypted_key_not_supported);
                [_ | _] ->
                    throw(multiple_key_not_supported)
            end
    end.

load_certs(FilePath) ->
    case filelib:is_dir(FilePath) of
        true -> load_cert_dir(FilePath, [".pem", ".crt"]);
        false -> load_cert_file(FilePath, ["", ".pem", ".crt"])
    end.


%--- Internal Functions --------------------------------------------------------

tls_server_trusted_certs(DomainName) ->
    case get_config_path(tls_server_trusted_certs) of
        undefined ->
            [];
        {ok, BasePath} ->
            FilePath = filename:join(BasePath, DomainName),
            try load_cert_file(FilePath, [".pem", ".crt"])
            catch throw:_Reason -> []
            end
    end.

tls_server_trusted_certs_cb() ->
    get_config_cb(tls_server_trusted_certs_cb, []).

tls_client_trusted_certs() ->
    DefaultClientPath = {priv, grisp_keychain, ""},
    BasePath = get_config_path(tls_client_trusted_certs, DefaultClientPath),
    try load_certs(BasePath)
    catch throw:_Reason -> []
    end.

tls_client_trusted_certs_cb() ->
    get_config_cb(tls_client_trusted_certs_cb, []).

tls_verify() ->
    case get_config(tls_verify) of
        undefined -> verify_peer;
        {ok, Value} when Value =:= verify_none; Value =:= verify_peer -> Value
    end.

domain_name(undefined) -> undefined;
domain_name(Name) when is_atom(Name) -> atom_to_list(Name);
domain_name(Name) when is_list(Name) -> Name;
domain_name(Name) when is_binary(Name) -> unicode:characters_to_list(Name).

server_name_indication(undefined) -> disabled;
server_name_indication(DomainName) -> DomainName.

locate_test_dir(BasePath) ->
    BuildTestDir = filename:join(BasePath, "test"),
    case filelib:is_dir(BuildTestDir) of
        true -> BuildTestDir;
        false ->
            SrcDir = filename:join(BasePath, "src"),
            case file:read_link(SrcDir) of
                {error, einval} ->
                    throw({test_directory_not_found, BasePath});
                {ok, SrcTargetDir} ->
                    AbsSrcTargetDir = filename:absname(SrcTargetDir, BasePath),
                    AbsSrcParentDir = filename:dirname(AbsSrcTargetDir),
                    SrcTestDir = filename:join(AbsSrcParentDir, "test"),
                    case filelib:is_dir(SrcTestDir) of
                        true -> SrcTestDir;
                        false ->
                            throw({test_directory_not_found, AbsSrcParentDir})
                    end
            end
    end.

load_cert_dir(DirPath, Extensions) ->
    case file:list_dir(DirPath) of
        {error, Reason} -> throw(Reason);
        {ok, Files} ->
            lists:foldl(fun(Filename, Acc) ->
                FullPath = filename:join(DirPath, Filename),
                Ext = filename:extension(Filename),
                IsFile = filelib:is_file(FullPath),
                HasExt = lists:member(Ext, Extensions),
                case IsFile andalso HasExt of
                    false -> Acc;
                    true -> load_cert_file(FullPath) ++ Acc
                end
            end, [], Files)
    end.

load_cert_file(FilePath, []) ->
    {ok, Cwd} = file:get_cwd(),
    throw({certificate_not_found, FilePath, Cwd});
load_cert_file(FilePath, [Ext | Rest]) ->
    FullPath = FilePath ++ Ext,
    case filelib:is_file(FullPath) of
        true -> load_cert_file(FullPath);
        false -> load_cert_file(FilePath, Rest)
    end.

load_cert_file(FilePath) ->
    case file:read_file(FilePath) of
        {error, enoent} ->
            throw({certificate_not_found, FilePath});
        {ok, PemData} ->
            decode_certs(PemData)
    end.

decode_certs(PemData) ->
    decode_certs(public_key:pem_decode(PemData), []).

decode_certs([], Acc) ->
    lists:reverse(Acc);
decode_certs([{'Certificate', DerData, not_encrypted} | Rest], Acc) ->
    decode_certs(Rest, [DerData | Acc]);
decode_certs([Bad | _Rest], _Acc) ->
    throw({bad_certificate, Bad}).
