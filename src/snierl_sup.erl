-module(snierl_sup).

-behaviour(supervisor).

-export([start_link/0, init/1]).

-define(SERVER, ?MODULE).

start_link() -> supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    Flags = #{stragegy => one_for_one},
    Specs0 = [
        #{id => snierl_listener},
        #{id => snierl_acme},
        #{id => snierl_proxy_sup, type => supervisor},
        #{id => snierl_con_sup, type => supervisor},
        #{id => snierl_acceptor_sup, type => supervisor}
    ],
    Specs = lists:map(
        fun(#{id := Id} = M) ->
            M#{start => {Id, start_link, []}}
        end,
        Specs0
    ),
    {ok, {Flags, Specs}}.
