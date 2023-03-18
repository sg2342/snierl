-module(snierl_acceptor).

-behaviour(gen_statem).

-export([init/1, callback_mode/0, handle_event/4, start_link/1]).

-ignore_xref({start_link, 1}).

start_link(Id) -> gen_statem:start_link(?MODULE, [Id], []).

callback_mode() -> [handle_event_function, state_enter].

init([Id]) -> {ok, undefined, #{id => Id, accepted => 0}}.

handle_event(enter, _, _, #{accepted := Accepted, id := Id} = D) ->
    {ok, LSock} = snierl_listener:socket(Id),
    {ok, Sock} = gen_tcp:accept(LSock),
    snierl_con:accepted(Sock),
    {repeat_state, D#{accepted => Accepted + 1}}.
