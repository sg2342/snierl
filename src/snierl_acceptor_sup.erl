-module(snierl_acceptor_sup).

-behaviour(supervisor).

-export([start_link/0, init/1]).
-ignore_xref({start_link, 0}).

-define(SERVER, ?MODULE).

start_link() -> supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    Flags = #{strategy => one_for_one},
    {ok, NumAcceptors} = application:get_env(num_acceptors),
    {ok, L} = application:get_env(listen),
    Specs = [
        #{
            id => Id,
            start => {snierl_acceptor, start_link, [Id]},
            modules => [snierl_acceptor]
        }
     || Id <- lists:seq(1, NumAcceptors * length(L))
    ],
    {ok, {Flags, Specs}}.
