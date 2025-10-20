-module(grisp_keychain).

-export([tls_options/1]).
-export([read_cert/2]).

tls_options(Domain) ->
    delegate_call(?FUNCTION_NAME, [Domain]).

read_cert(primary, der) ->
    delegate_call(?FUNCTION_NAME, [primary, der]).

% Internal functions -----------------------------------------------------------

delegate_call(Function, Args) ->
    {ok, Module} = application:get_env(grisp_keychain, api_module),
    erlang:apply(Module, Function, Args).
