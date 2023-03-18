-module(snierl_con).

-behaviour(gen_statem).

-export([accepted/1]).

-export([init/1, callback_mode/0, handle_event/4, start_link/0]).

-ignore_xref({start_link, 0}).
-ignore_xref({behaviour_info, 1}).

-type proxy_map() :: #{
    tls := ssl:sslsocket(),
    hs_opts := [ssl:tls_option()],
    atom() => term()
}.
-export_type([proxy_map/0]).
-callback proxy(proxy_map()) -> ok | {error, term()}.

-spec accepted(gen_tcp:socket()) -> ok.
accepted(Socket) ->
    {ok, Pid} = snierl_con_sup:start_child(),
    ok = gen_tcp:controlling_process(Socket, Pid),
    gen_statem:cast(Pid, {accepted, Socket}).

start_link() -> gen_statem:start_link(?MODULE, [], []).

callback_mode() -> handle_event_function.

init([]) -> {ok, undefined, #{}, timer:seconds(2)}.

handle_event(timeout, _, undefined, _) ->
    stop;
handle_event(cast, {accepted, Socket}, undefined, #{}) ->
    {ok, Opts} = application:get_env(tls_opts),
    tls_accept(ssl:handshake(Socket, [{log_level, info} | Opts], 1000)).

tls_accept(
    {ok, HsSock, #{
        sni := HostName,
        alpn := <<"\nacme-tls/1">>
    }}
) ->
    tls_accept1(HsSock, snierl_acme:alpn_lookup(HostName));
tls_accept({ok, HsSocket, #{sni := HostName}}) ->
    {ok, L} = application:get_env(sni_hosts),
    tls_accept1(HsSocket, lists:keyfind(HostName, 1, L));
tls_accept(_) ->
    stop.

tls_accept1(HsSock, {HostName, #{hs_opts := acme} = M}) ->
    tls_accept1(HsSock, snierl_acme:set_hs_opts(HostName, M));
tls_accept1(HsSock, {HostName, #{hs_opts := Opts} = M}) ->
    tls_accept2(ssl:handshake_continue(HsSock, Opts), M#{sni => HostName});
tls_accept1(_HsSock, false) ->
    stop.

tls_accept2({ok, Tls}, #{ext := _Ext} = M) ->
    tls_accept3(ssl:peercert(Tls), Tls, M);
tls_accept2({ok, Tls}, #{dst := Dst} = M) ->
    proxy(Tls, Dst, M);
tls_accept2(_, _) ->
    stop.

tls_accept3(
    {ok, DER},
    Tls,
    #{ext := #{oid := OID, dsts := Dsts}, dst := Default} = M
) ->
    Dst = proplists:get_value(snierl_crts:extension(OID, DER), Dsts, Default),
    proxy(Tls, Dst, M);
tls_accept3({error, no_peercert}, Tls, #{dst := Dst} = M) ->
    proxy(Tls, Dst, M);
tls_accept3(_, _, _) ->
    stop.

proxy(Tls, {Module, #{} = Map}, #{hs_opts := HsOpts, sni := HostName}) when
    is_atom(Module)
->
    Module:proxy(Map#{tls => Tls, hs_opts => HsOpts, sni => HostName}),
    stop;
proxy(Tls, Module, #{hs_opts := HsOpts, sni := HostName}) when
    is_atom(Module)
->
    Module:proxy(#{tls => Tls, hs_opts => HsOpts, sni => HostName}),
    stop;
proxy(Tls, {_Addr, _Port} = Dst, #{hs_opts := HsOpts}) ->
    snierl_proxy:proxy(#{tls => Tls, hs_opts => HsOpts, dst => Dst}),
    stop.
