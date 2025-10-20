%%%-------------------------------------------------------------------
%% @doc grisp_keychain public API
%% @end
%%%-------------------------------------------------------------------

-module(grisp_keychain_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    grisp_keychain_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
