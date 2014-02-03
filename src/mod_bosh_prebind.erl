-module(mod_bosh_prebind).

-behaviour(gen_mod).
-behaviour(cowboy_loop_handler).

%% gen_mod callbacks
-export([start/2,
         stop/1]).

%% cowboy_loop_handler callbacks
-export([init/3,
         info/3,
         terminate/3]).

start(_Host, _Opts) ->
    ok.

stop(_Host) ->
    ok.

-include_lib("ejabberd_mim/apps/ejabberd/include/ejabberd.hrl").
-include_lib("ejabberd_mim/apps/ejabberd/include/jlib.hrl").
-include_lib("ejabberd_mim/apps/ejabberd/include/mod_bosh.hrl").
-include_lib("exml/include/exml_stream.hrl").

-define(MBP_FORWARD, mod_bosh).

-define(DEFAULT_MAX_AGE, 1728000).  %% 20 days in seconds
-define(DEFAULT_ALLOW_ORIGIN, <<"*">>).

-record(mbp_bind_data,
        {
         rid :: non_neg_integer(),
         sid,
         jid
        }
       ).

-record(mbp_auth_data,
        {
         to,
         from,
         password
        }
       ).

%% Request State
-record(mbp_rstate,
        {
         step = parse :: parse | start | auth | stream_restart | bind | session,
         bind_data :: #mbp_bind_data{},
         auth_data :: #mbp_auth_data{}
        }
       ).
%%--------------------------------------------------------------------
%% cowboy_loop_handler callbacks
%%--------------------------------------------------------------------

init(Transport, Req, Opts) ->
    %% mod_bosh doesn't use/introspect the state, so replace with our own.
    %%  futureproofing in case it starts using that:
    %%  add an "extra" field to that record type, hide our state in that.
    {loop, NewReq, _} = ?MBP_FORWARD:init(Transport, Req, Opts),
    State = #mbp_rstate{
                step = parse
            },
    {loop, NewReq, State}.

info(forward_body, Req, State) when State#mbp_rstate.step == parse ->
    %% we're not expecting much here, change to cowboy_req:body(MaxBodyLength, Req)
    Req1 = reset_peer(Req),
    {ok, Body, Req2} = cowboy_req:body(Req1),
    %% TODO: headers (XFF) (maybe on output? - no, parse early for rate limit, etc.)
    {ok, BodyElem} = exml:parse(Body),
    ?DEBUG("Parsed body: ~p~n", [BodyElem]),
%% 	XmppDomain = exml_query:attr(BodyElem, <<"to">>),
    Rid = try
        binary_to_integer(exml_query:attr(BodyElem, <<"rid">>))
    catch
        error:badarg -> undefined
    end,
    AuthData0 = extract_auth_data(BodyElem),
    AuthData = case AuthData0#mbp_auth_data.from of
                   undefined ->
                       AuthData0#mbp_auth_data{ from = <<"anonymous">> };
                   _ ->
                       AuthData0
               end,
    %% if Rid == undefined: bail
    %% verify AuthData or bail
    %% made it this far? create bind request
    StartAttrsXml = [
    {<<"rid">>, integer_to_binary(Rid)},
    {<<"to">>, AuthData#mbp_auth_data.to},
    {<<"from">>, AuthData#mbp_auth_data.from},
    {<<"xml", ":", "lang">>, <<"en">>},
    {<<"content">>, <<"text/xml; charset=utf-8">>},
    {<<"ver">>, <<"1.6">>},
    {<<"xmpp", ":", "version">>, <<"1.0">>},
    {<<"xmlns">>, ?NS_HTTPBIND},
    %% TODO: grab wait/hold from BodyElem
    {<<"wait">>, <<"60">>},
    {<<"hold">>, <<"1">>}
    ],
    StartBody = #xmlel{name = <<"body">>, attrs = StartAttrsXml},
    NewState = State#mbp_rstate{
                step = start,
                auth_data = AuthData,
                bind_data = #mbp_bind_data{rid = Rid + 1}
                },
    %% TODO: replace with start_session (faster, get socket back)
    ?MBP_FORWARD:forward_body(Req2, StartBody, NewState);

%%<body
%% maxpause='120'
%% inactivity='30'
%$ xmlns:stream='http://etherx.jabber.org/streams'
%% xmlns:xmpp='urn:xmpp:xbosh'
%% xmlns='http://jabber.org/protocol/httpbind'
%% xmpp:version='1.0'
%% xmpp:restartlogic='true'
%% sid='eb095fbef6d4f1669e011aa60848118323b88a52'
%% accept='deflate,gzip'
%% from='localhost'
%% hold='1'
%% requests='2'
%% wait='60'>
%%     <stream:features>
%%         <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
%%              <mechanism>PLAIN</mechanism>
%%              <mechanism>DIGEST-MD5</mechanism>
%%         </mechanisms>
%%         <register xmlns='http://jabber.org/features/iq-register'/>
%%     </stream:features>
%% </body>

info({bosh_reply, El}, Req,
     #mbp_rstate{ auth_data = AuthData,
                  bind_data = #mbp_bind_data{ rid = Rid } = BindData} = State
    ) when State#mbp_rstate.step == start ->
    %%TODO: unpack this in method signature
    ?DEBUG("Caught El, Req, State: ~p~n", [{El, Req, State}]),
    Sid = exml_query:attr(El, <<"sid">>),
    Attrs = [
        {<<"rid">>, integer_to_binary(Rid)},
        {<<"sid">>, Sid},
        {<<"xmlns">>, ?NS_HTTPBIND}
    ],
    AuthPayload = auth_payload(AuthData),
    AuthBody = #xmlel{name = <<"body">>,
                      attrs = Attrs,
                      children = AuthPayload},
    NewState = State#mbp_rstate{
                step = auth,
                auth_data = AuthData,
                bind_data = BindData#mbp_bind_data{rid = Rid + 1,
                                           sid = Sid}
                },
    ?MBP_FORWARD:forward_body(Req, AuthBody, NewState);

%% r = s.post('http://localhost:5280/http-pre-bind/', """<body to='localhost' rid='8589934590' wait='60' hold='1' from='cstelma@localhost' password='foobar'/>""");
%% "<body xmlns='http://jabber.org/protocol/httpbind' sid='2fee976fb368ff88927b088e5d54206b92e7ca9b'><failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure></body>"
%% r = s.post('http://localhost:5280/http-pre-bind/', """<body to='localhost' rid='8589934590' wait='60' hold='1' from='cstelma@localhost' password='foobar'/>""");
%% "<body xmlns='http://jabber.org/protocol/httpbind' sid='8e2d569435d693417a57629d7642277794ecbe99'><success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/></body>"

info({bosh_reply, El}, Req,
     #mbp_rstate{ auth_data = AuthData,
                  bind_data = #mbp_bind_data{ rid = Rid,
                                              sid = Sid } = BindData } = State
    ) when State#mbp_rstate.step == auth ->
    ?DEBUG("Caught El, Req, State: ~p~n", [{El, Req, State}]),
    Attrs = [
        {<<"rid">>, integer_to_binary(Rid)},
        {<<"sid">>, Sid},
        {<<"to">>, AuthData#mbp_auth_data.to},
        {<<"xml", ":", "lang">>, <<"en">>},
        {<<"xmpp", ":", "restart">>, <<"true">>},
        {<<"xmlns">>, ?NS_HTTPBIND}
    ],
    RestartBody = #xmlel{name = <<"body">>,
                         attrs = Attrs},
    NewState = State#mbp_rstate{
                step = stream_restart,
                bind_data = BindData#mbp_bind_data{rid = Rid + 1}
                },
    ?MBP_FORWARD:forward_body(Req, RestartBody, NewState);
info({bosh_reply, El}, Req,
     #mbp_rstate{ bind_data = #mbp_bind_data{ rid = Rid,
                                              sid = Sid } = BindData } = State
    ) when State#mbp_rstate.step == stream_restart ->
    %%TODO: check that we've got the right El
  Attrs = [
    {<<"rid">>, integer_to_binary(Rid)},
    {<<"sid">>, Sid},
    {<<"xmlns">>, ?NS_HTTPBIND}
  ],
  Payload = [#xmlel{
        name = <<"iq">>,
        attrs = [
            {<<"type">>, <<"set">>},
            {<<"id">>, <<"bind_1">>},
            {<<"xmlns">>, <<"jabber:client">>}
        ],
        children = [
            #xmlel{
                name = <<"bind">>,
                attrs = [
                    {<<"xmlns">>, ?NS_BIND}
                ],
                children = [
%% TODO: return clever resource name
%%                     #xmlel{name = <<"resource">>,
%%                         children = [{xmlcdata, <<"httpclient">>}]
%%                     }
                ]
            }
        ]
    }],
    BindBody = #xmlel{name = <<"body">>,
                      attrs = Attrs,
                      children = Payload},
    NewState = State#mbp_rstate{
                step = bind,
                bind_data = BindData#mbp_bind_data{rid = Rid + 1}
                },
    ?MBP_FORWARD:forward_body(Req, BindBody, NewState);
info({bosh_reply, El}, Req,
     #mbp_rstate{ bind_data = #mbp_bind_data{ rid = Rid,
                                              sid = Sid } = BindData } = State
    ) when State#mbp_rstate.step == bind ->
%%"<body xmlns='http://jabber.org/protocol/httpbind'
%%  sid='de240cdd8d73360b4bd4e3c77cbb7bf3eeca6aec'>
%% 		 <iq type='result'
%% 			   id='bind_1'>
%% 			<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>
%%          <jid>cstelma@localhost/927101185137954419414136</jid>
%%			</bind>
%%		</iq>
%%	</body>"
    Jid = exml_query:path(El, [{element, <<"iq">>},
                                 {element, <<"bind">>},
                                 {element, <<"jid">>},
                                 cdata]),
  Attrs = [
    {<<"rid">>, integer_to_binary(Rid)},
    {<<"sid">>, Sid},
    {<<"xmlns">>, ?NS_HTTPBIND}
  ],
  Payload = [#xmlel{
        name = <<"iq">>,
        attrs = [
            {<<"type">>, <<"set">>},
            {<<"id">>, <<"_session_auth_2">>},
            {<<"xmlns">>, <<"jabber:client">>}
        ],
        children = [
            #xmlel{
                name = <<"session">>,
                attrs = [
                    {<<"xmlns">>, ?NS_SESSION}
                ]
            }
        ]
    }],
    SessionBody = #xmlel{name = <<"body">>,
                      attrs = Attrs,
                      children = Payload},
    NewState = State#mbp_rstate{
                step = session,
                bind_data = BindData#mbp_bind_data{rid = Rid + 1,
                                                   jid = Jid}
                },
    ?MBP_FORWARD:forward_body(Req, SessionBody, NewState);
info({bosh_reply, El}, Req,
     #mbp_rstate{ bind_data = #mbp_bind_data{ rid = Rid,
                                              sid = Sid,
                                              jid = Jid } } = State
    ) when State#mbp_rstate.step == session ->
    %% TODO: validate return and/or loop
    Json = mochijson2:encode({struct, [
              {rid, integer_to_binary(Rid)},
              {sid, Sid},
              {jid, Jid}
              ]}),
    BJson = iolist_to_binary(Json),
    ?DEBUG("Sending (binary) to ~p: ~p~n", [Sid, BJson]),
    {ok, Req1} = cowboy_req:reply(200, [{<<"content-type">>, <<"application/json">>},
                                        ac_allow_origin(?DEFAULT_ALLOW_ORIGIN),
                                        ac_allow_methods(),
                                        ac_allow_headers(),
                                        ac_max_age()], BJson, Req),
    {ok, Req1, State};
info({bosh_reply, El}, Req, State) ->
    ?MBP_FORWARD:info({bosh_reply, El}, Req, State);
info(Other, Req, State) ->
    ?MBP_FORWARD:info(Other, Req, State).

terminate(Reason, Req, State) ->
    ?MBP_FORWARD:terminate(Reason, Req, State).

extract_auth_data(Body) ->
    #mbp_auth_data
        {
         to         = exml_query:attr(Body, <<"to">>),
         from       = exml_query:attr(Body, <<"from">>),
         password   = exml_query:attr(Body, <<"password">>)
        }.

%%TODO: more checks around from/password
auth_payload(#mbp_auth_data{from = From, password = Password}) when is_binary(From), is_binary(Password)  ->
    Jid = jlib:binary_to_jid(From),
    InitialResponse = iolist_to_binary([0, jlib:jid_to_binary(Jid), 0, Password]),
    [selected_mechanism(<<"PLAIN">>, InitialResponse)];
auth_payload(_AuthData) ->
    [selected_mechanism(<<"ANONYMOUS">>)].

selected_mechanism(Mechanism) ->
    #xmlel{name = <<"auth">>,
           attrs = [
                    {<<"xmlns">>, ?NS_SASL},
                    {<<"mechanism">>, Mechanism}
                   ]
          }.
selected_mechanism(Mechanism, Initial_Response) ->
    El = selected_mechanism(Mechanism),
    El#xmlel{children = [#xmlcdata{content = base64:encode(Initial_Response)}]}.

%%convert_response_from_bosh() ->
    %%something we don't want

%%convert_state_to_bosh(#mbp_rstate{} = State) ->
    %%blah

ac_allow_origin(Origin) ->
    {<<"Access-Control-Allow-Origin">>, Origin}.

ac_allow_methods() ->
    {<<"Access-Control-Allow-Methods">>, <<"POST, OPTIONS">>}.

ac_allow_headers() ->
    {<<"Access-Control-Allow-Headers">>, <<"Content-Type">>}.

ac_max_age() ->
    {<<"Access-Control-Max-Age">>, integer_to_binary(?DEFAULT_MAX_AGE)}.

header_values(Name, Headers) ->
    lists:filtermap(
        fun (Elem) ->
            case Elem of
                {Name, Val} -> {true, Val};
                _ -> false
            end
        end,
        Headers
    ).

tokenized_combined_header(Name, Headers) ->
    lists:flatten(
        [cowboy_http:list(X, fun cowboy_http:token/2) ||
         X <- header_values(Name, Headers)]
    ).

reset_peer(Req) ->
    {Headers, Req2} = cowboy_req:headers(Req),
    {{IPLast, ClientPort}, Req3} = cowboy_req:peer(Req2),
    XFFs = tokenized_combined_header(<<"x-forwarded-for">>, Headers),
    [ClientIP | ProxiesIPs] = XFFs ++ [iolist_to_binary(inet:ntoa(IPLast))],
    Client = case filtered_reversed_ipchain(ProxiesIPs) of
        [] -> ClientIP;
        [FirstUntrusted | _] -> FirstUntrusted
    end,
    {ok, IPClient} = inet:parse_address(binary_to_list(Client)),
    if
        IPClient =/= IPLast ->
            ?DEBUG("The IP ~w was replaced with ~w due to "
                   "header X-Forwarded-For: ~p",
                   [IPLast, IPClient, XFFs]);
        true -> ok
    end,
    cowboy_req:set([{peer, {IPClient, ClientPort}}], Req3).

filtered_reversed_ipchain(Chain) ->
    lists:dropwhile(fun is_trusted_ip/1, lists:reverse(Chain)).

is_trusted_ip(_) -> false.

