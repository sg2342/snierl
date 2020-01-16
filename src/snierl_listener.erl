-module(snierl_listener).

-behaviour(gen_statem).

-export([init/1, callback_mode/0, handle_event/4, start_link/0, terminate/3]).
-ignore_xref({start_link, 0}).

-export([socket/0]).

-define(SERVER, ?MODULE).


-spec socket() -> {ok, gen_tcp:socket()}.
socket() -> gen_statem:call(?SERVER, socket).


start_link() -> gen_statem:start_link({local, ?SERVER}, ?MODULE, [], []).


callback_mode() -> [handle_event_function, state_enter].


init([]) -> {ok, undefined, #{}}.


handle_event(enter, _, _, #{}) ->
    {ok, Port} = application:get_env(listen_port),
    Opts = [binary, {active, false}],
    {ok, Socket} = gen_tcp:listen(Port, Opts),
    {keep_state, #{ socket => Socket }};
handle_event({call, Acceptor}, socket, _, #{socket := Socket}) ->
    {keep_state_and_data, [{reply, Acceptor, {ok, Socket}}]}.


terminate(_Reason, _State, #{ socket := Socket }) -> gen_tcp:close(Socket).
