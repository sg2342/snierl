-module(snierl_acceptor).

-behavior(gen_statem).

-export([init/1, callback_mode/0, handle_event/4, start_link/0]).

-ignore_xref({start_link, 0}).


start_link() -> gen_statem:start_link(?MODULE, [], []).


callback_mode() -> [handle_event_function, state_enter].


init([]) -> {ok, undefined, #{accepted => 0}}.


handle_event(enter, _, _, #{ accepted := Accepted }) ->
    {ok, LSock} = snierl_listener:socket(),
    {ok, Sock} = gen_tcp:accept(LSock),
    snierl_con:accepted(Sock),
    {repeat_state, #{ accepted => Accepted + 1 }}.
