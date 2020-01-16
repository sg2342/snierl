-module(snierl_proxy_sup).

-behaviour(supervisor).

-export([start_link/0, init/1, start_child/0]).

-ignore_xref({start_link, 0}).

-define(SERVER, ?MODULE).


start_link() -> supervisor:start_link({local, ?SERVER}, ?MODULE, []).


start_child() -> supervisor:start_child(?MODULE, []).


init([]) ->
    Flags = #{ strategy => simple_one_for_one },
    Specs = [ #{ id => snierl_proxy
               , restart => temporary
               , shutdown => brutal_kill
               , start => {snierl_proxy, start_link, []} }],
    {ok, {Flags, Specs}}.
