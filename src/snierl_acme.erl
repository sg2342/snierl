-module(snierl_acme).

-behaviour(acmerl_challenge).
-behaviour(acmerl_json).
-behaviour(acmerl_http).
-behaviour(gen_statem).

%% snierl_con
-export([set_hs_opts/2, alpn_lookup/1]).
%% acmerl_json callbacks
-export([encode/2, decode/2]).
%% acmerl_http callback
-export([request/5]).
%% acmerl_challenge callbacks:
-export([challenge_type/0, deploy/2, remove/2]).
%% gen_statem
-export([init/1, callback_mode/0, handle_event/4, start_link/0]).

-ignore_xref({start_link, 0}).

-define(SERVER, ?MODULE).
-define(TAB, ?SERVER).


alpn_lookup(Name) -> gen_statem:call(?SERVER, {alpn_lookup, Name}).


set_hs_opts(Name, M) -> set_hs_opts1(ets:lookup(?TAB, Name), M).

set_hs_opts1([],_) -> false;
set_hs_opts1([{Name, #{hs_opts := Opts}}], M) -> {Name, M#{hs_opts => Opts}}.


deploy(D, _) -> gen_statem:call(?SERVER, {deploy, D}).


remove(Name, _) -> gen_statem:cast(?SERVER, {remove, Name}).


challenge_type() -> <<"tls-alpn-01">>.


encode(Term, _) -> jsone:encode(Term).


decode(Term, _) -> jsone:decode(Term).


request(Method, Url, Headers, Body, _) ->
    request1( request0(Method), binary_to_list(Url)
	    , [{binary_to_list(K), binary_to_list(V)} || {K,V} <- Headers]
	    , Body).

request1(post, Url, Headers, Body) ->
    ContentT = binary_to_list(proplists:get_value(<<"content-type">>, Headers,
						  <<"application/jose+json">>)),
    request2(httpc:request(post, {Url, Headers, ContentT, Body},
			   [], [{body_format, binary}]));
request1(Method, Url, Headers, _) ->
    request2(httpc:request(Method, {Url, Headers}, [], [{body_format, binary}])).

request2({ok, {{_HttpVersion, Status, _Reason}, Headers, Body}}) ->
    {ok, Status,
     [{list_to_binary(string:lowercase(K)), list_to_binary(V)} ||
	 {K,V} <- Headers], Body};
request2({error, _} = Err) -> Err.

request0('HEAD') -> head;
request0('GET') -> get;
request0('POST') -> post.


start_link() -> gen_statem:start_link({local, ?SERVER}, ?MODULE, [], []).


callback_mode() -> handle_event_function.


init([]) -> {ok, undefined, #{ alpn_validation => #{} }, 0}.


handle_event(timeout, _, _State, M) ->
    Key = public_key:generate_key({rsa, 2048, 65537}),
    KeyDER = {'RSAPrivateKey', public_key:der_encode('RSAPrivateKey', Key)},
    {ok, Account} = account(application:get_env(acme_account_file)),
    init_table(),
    check_for_action(M#{ account => Account
		       , alpn_key => Key
		       , alpn_key_der => KeyDER });
handle_event(state_timeout, _, _State, M) -> check_for_action(M);
handle_event({call, From}, {alpn_lookup, Name}, _State,
	     #{ alpn_key_der := Key, alpn_validation := V }) ->
    R = case maps:get(Name, V, false) of
	    false -> false;
	    Cert -> {Name, #{ hs_opts => [ {key, Key}, {cert, Cert}
					 , { alpn_preferred_protocols
					   , [<<"acme-tls/1">>] }
					 ] }}
	end,
    {keep_state_and_data, [{reply, From, R}]};
handle_event({call, From}, {deploy, #{ identifier := BinName
				     , key_auth := KeyAuth}},
	     _State, #{ alpn_key := Key, alpn_validation := V } = M) ->
    Name = binary_to_list(BinName),
    Cert = snierl_crts:alpn(Key, Name, KeyAuth),
    {keep_state, M#{ alpn_validation => V#{ Name => Cert} },
     [{reply, From, {ok, Name}}]};
handle_event(cast, {remove, Name}, _State, #{ alpn_validation := V } = M) ->
    {keep_state, M#{ alpn_validation => maps:remove(Name, V) }};
handle_event(cast, {insert, {Name, Map}}, _State, _M) ->
    dump_to_dets(do_insert(Name, Map)),
    keep_state_and_data.

do_insert(Name, Map) ->
    {ok, L} = application:get_env(sni_hosts),
    do_insert1(lists:keyfind(Name, 1, L), Map).

do_insert1({Name, #{ hs_opts := acme, hs_extra := Extra}},
	   #{ hs_opts := Opts} = Map) ->
    ets:insert(?TAB, {Name, Map#{ hs_opts => extra_hs_opts(Extra, Opts) }});
do_insert1({Name, #{ hs_opts := acme }}, Map) ->
    ets:insert(?TAB, {Name, Map});
do_insert1(_,_) -> false.


extra_hs_opts([], Opts) -> Opts;
extra_hs_opts([{key, _}|T], Opts) -> extra_hs_opts(T, Opts);
extra_hs_opts([{cert, _}|T], Opts) -> extra_hs_opts(T, Opts);
extra_hs_opts([{certfile, _}|T], Opts) -> extra_hs_opts(T, Opts);
extra_hs_opts([{keyfile, _}|T], Opts) -> extra_hs_opts(T, Opts);
extra_hs_opts([{cacertfile, _} = V|T], Opts) ->
    extra_hs_opts(T, extra_hs_opts1(V, Opts));
extra_hs_opts([{cacerts, _} = V|T], Opts) ->
    extra_hs_opts(T, extra_hs_opts1(V, Opts));
extra_hs_opts([O|T], Opts) -> extra_hs_opts(T, [O|Opts]).

extra_hs_opts1({cacertfile, F}, Opts) ->
    {ok, PemBin} = file:read_file(F),
    L = [C || {'Certificate', C, _} <- public_key:pem_decode(PemBin)],
    extra_hs_opts1({cacerts, L}, Opts);
extra_hs_opts1({cacerts, L}, Opts0) ->
    {value, {cacerts, Acme}, Opts} = lists:keytake(cacerts, 1, Opts0),
    [{cacerts, L ++ Acme} | Opts].


check_for_action(#{ account := Account} = M) ->
    Seconds = calendar:datetime_to_gregorian_seconds({date(), time()}),
    Cutoff = Seconds + 60 * 60 * 24 * 7,
    {ok, L0} = application:get_env(sni_hosts),
    L = [ Name || {Name, #{ hs_opts := acme } } <- L0 ],
    check_for_action1(ets:first(?TAB), Cutoff, Account, L),
    {keep_state, M, [{state_timeout, timer:hours(1), check}]}.

check_for_action1('$end_of_table', _Cutoff, Account, Hosts) ->
    lists:foreach(fun(H) -> acme_worker(Account, H) end, Hosts);
check_for_action1(H, Cutoff, Account, Hosts0) ->
    Maybe = lists:member(H, Hosts0),
    Hosts = check_for_action2(Maybe, H, Cutoff, Account, Hosts0),
    check_for_action1(ets:next(?TAB, H), Cutoff, Account, Hosts).

check_for_action2(false, H, _, _, Hosts) -> ets:delete(?TAB, H), Hosts;
check_for_action2(true, H, Cutoff, Account, Hosts) ->
    check_for_action3(ets:lookup(?TAB, H), Cutoff, Account),
    lists:delete(H, Hosts).

check_for_action3([{H, #{ expires := Ex }}], Cutoff, Account)
  when Ex < Cutoff ->  acme_worker(Account, H);
check_for_action3(_,_,_) -> ok.


account({ok, FN}) -> account1(file:read_file(FN), FN).

account1({ok, Bin}, _) -> acmerl:import_account(jsone:decode(Bin));
account1(_, FN) ->
    {ok, Client} = new_client(),
    {ok, Account} = acmerl:new_account(Client,
				       #{<<"termsOfServiceAgreed">> => true}),
    ok = file:write_file(FN, jsone:encode(acmerl:export_account(Account))),
    {ok, Account}.


acme_worker(Account, Name) ->
    spawn(
      fun () ->
	      Key = public_key:generate_key({rsa, 2048, 65537}),
	      CSR = snierl_crts:csr(Key, Name),
	      KeyDER = {'RSAPrivateKey',
			public_key:der_encode('RSAPrivateKey', Key)},
	      Handler = JsonCodec = {?MODULE, []},
	      {ok, Client} =  new_client(),
	      OrderOpts = #{ <<"identifiers">> =>
				 [ #{ <<"type">> => <<"dns">>
				    , <<"value">> => list_to_binary(Name) } ] },
	      {ok, Order} = acmerl:new_order(Client, Account, OrderOpts),
	      {ok, Authzs} = acmerl:order_authorizations(Client, Account, Order),
	      {ok, Deployed} = acmerl:deploy_challenges(Account, Handler,
							JsonCodec, Authzs),
	      ok = acmerl:validate_challenges(Client, Account, Handler, Deployed),
	      {ok, Pems} = acmerl:finalize_and_fetch(Client, Account, Order, CSR),
	      {Expires, Cert, CaCerts} = snierl_crts:of_pem(Pems, Name),
	      HsOpts = [{key, KeyDER}, {cert, Cert}, {cacerts, CaCerts}],
	      gen_statem:cast(?SERVER, {insert,
					{Name, #{ hs_opts => HsOpts
						, expires => Expires }}})
      end).


new_client() ->
    {ok, DirectoryUrl} = application:get_env(acme_directory_url),
    acmerl:new_client(DirectoryUrl, #{ http_module => ?MODULE
				     , json_module => ?MODULE }).


init_table() ->
    {ok, DetsF} = application:get_env(acme_certs_dets),
    {ok, ?TAB} = dets:open_file(?TAB, [{file, DetsF}, {repair, force}]),
    ?TAB = ets:new(?TAB, [set, named_table, protected]),
    ?TAB = dets:to_ets(?TAB, ?TAB),
    dets:close(?TAB).


dump_to_dets(false) -> ok;
dump_to_dets(true) ->
    {ok, DetsF} = application:get_env(acme_certs_dets),
    {ok, ?TAB} = dets:open_file(?TAB, [{file, DetsF}, {repair, force}]),
    ?TAB = ets:to_dets(?TAB,?TAB),
    dets:close(?TAB).
