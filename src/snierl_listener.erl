-module(snierl_listener).

-behaviour(gen_statem).

-export([init/1, callback_mode/0, handle_event/4, start_link/0, terminate/3]).
-ignore_xref({start_link, 0}).

-export([socket/1]).

-define(SERVER, ?MODULE).

-spec socket(Id :: integer()) -> {ok, gen_tcp:socket()}.
socket(Id) -> gen_statem:call(?SERVER, {socket, Id}).

start_link() -> gen_statem:start_link({local, ?SERVER}, ?MODULE, [], []).

callback_mode() -> [handle_event_function, state_enter].

init([]) -> {ok, undefined, #{}}.

handle_event(enter, _, _, #{}) ->
    {ok, L0} = application:get_env(listen),
    L = lists:map(
        fun({Port, Opts}) ->
            {ok, S} = gen_tcp:listen(Port, [binary, {active, false} | Opts]),
            S
        end,
        L0
    ),
    {keep_state, #{sockets => L}};
handle_event({call, Acceptor}, {socket, Id}, _, #{sockets := L}) ->
    S = lists:nth((Id rem length(L)) + 1, L),
    {keep_state_and_data, [{reply, Acceptor, {ok, S}}]}.

terminate(_Reason, _State, #{sockets := L}) ->
    lists:foreach(fun gen_tcp:close/1, L).
