-module(snierl_proxy).

-behaviour(gen_statem).
-behaviour(snierl_con).

-export([proxy/1]).

-export([init/1, callback_mode/0, handle_event/4, start_link/0, terminate/3]).

-ignore_xref({start_link, 0}).

-spec proxy(snierl_con:proxy_map()) -> ok.
proxy(#{tls := Tls, dst := {Addr, Port}}) ->
    {ok, Pid} = snierl_proxy_sup:start_child(),
    ok = ssl:controlling_process(Tls, Pid),
    gen_statem:cast(Pid, {Tls, {Addr, Port}}).

start_link() -> gen_statem:start_link(?MODULE, [], []).

callback_mode() -> [handle_event_function, state_enter].

init([]) -> {ok, undefined, #{}, timer:seconds(2)}.

terminate(_Reason, tls_proxy, #{tls := Tls, tcp := Tcp}) ->
    gen_tcp:close(Tcp),
    ssl:close(Tls);
terminate(_Reason, _State, _Data) ->
    ok.

handle_event(enter, undefined, tls_proxy, #{tls := Tls}) ->
    ok = ssl:setopts(Tls, [{active, true}]),
    keep_state_and_data;
handle_event(enter, _, _, #{}) ->
    keep_state_and_data;
handle_event(timeout, _, undefined, _) ->
    stop;
handle_event(info, {ssl, Tls, Bin}, tls_proxy, #{tls := Tls, tcp := Tcp}) ->
    maybe_stop(gen_tcp:send(Tcp, Bin));
handle_event(info, {tcp, Tcp, Bin}, tls_proxy, #{tls := Tls, tcp := Tcp}) ->
    maybe_stop(ssl:send(Tls, Bin));
handle_event(info, _Info, tls_proxy, _) ->
    stop;
handle_event(cast, {Tls, {Addr, Port}}, undefined, #{}) ->
    setup_proxy(Tls, Addr, Port).

maybe_stop(ok) -> keep_state_and_data;
maybe_stop(_) -> stop.

setup_proxy(Tls, Addr, Port) ->
    MayBe = gen_tcp:connect(Addr, Port, [binary, {active, true}], 500),
    setup_proxy1(MayBe, Tls).

setup_proxy1({ok, Tcp}, Tls) ->
    {next_state, tls_proxy, #{tls => Tls, tcp => Tcp}};
setup_proxy1(_, _) ->
    stop.
