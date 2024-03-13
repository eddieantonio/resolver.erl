-module(dns_server).
-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-include("include/dns.hrl").

-define(NAME, ?MODULE).
-record(state, {socket, cache}).


% Public API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_link(Port) ->
  gen_server:start_link({local, ?NAME}, ?MODULE, [Port], [{debug, [trace]}]).


% gen_server callbacks %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init([Port]) ->
  IP = {127,0,0,1},
  {ok, Socket} = gen_udp:open(Port, [binary, {ip, IP}, {active, true}]),
  io:format("[~p] Listening on ~w:~p~n", [?NAME, IP, Port]),
  {ok, #state{socket=Socket, cache=dns_cache:new()}}.

handle_call(_Message, _From, State) ->
  {noreply, State}.

handle_cast(_, State) ->
  {noreply, State}.

% DNS Query from UDP port
handle_info({udp, Socket, Host, Port, Datagram}, #state{cache=Cache} =State) ->
  Packet = dns_parse:packet(Datagram),
  #{id := ID, questions := [Question|_]} = Packet,
  Name = name(Question),
  {UpdatedCache, Result} = resolve(Name, Cache),
  % Just crash if we fail to resolve
  {ok, Addresses} = Result,
  Answers = [make_fake_record(Name, A) || A <- Addresses],
  Response = dns_query:build_response(ID, [Question], Answers),
  ok = gen_udp:send(Socket, Host, Port, Response),
  {noreply, State#state{cache=UpdatedCache}}.

terminate(_, #state{socket=Socket}) ->
  ok = gen_udp:close(Socket),
  ok.


% Internal %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type resolve_result() :: {ok, [inet:ip4_address()]} | {error, nxdomain}.

-spec resolve(string(), dns_cache:storage()) -> {dns_cache:storage(), resolve_result()}.
resolve(Name, Cache) ->
  CacheResult = dns_cache:get_records(Cache, a, Name),
  process_cache_result(Name, CacheResult).

process_cache_result(_, {Cache, {hit, Records}}) ->
  % In cache! Just return the addresses.
  {Cache, {ok, addresses(Records)}};
process_cache_result(Name, {Cache, miss}) ->
  % Not in cache. Do DNS resolution, and cache those records!
  {ok, #{answers := Answers}} = dns_resolver:send_query(Name, a),
  UpdatedCache = dns_cache:add_records(Cache, Answers),
  Result = case addresses(Answers) of
             [] -> {error, nxdomain};
             Addresses -> {ok, Addresses}
           end,
  {UpdatedCache, Result}.


%% @doc Return the domain name from a question.
name(#dns_question{name = Name}) -> Name.

%% @doc I haven't implemented this correctly, so this will have to do for now.
make_fake_record(Name, Address) ->
  FakeTTL = 3600, % Just make something up.
  #dns_record{name = Name, type = a, class = in,
              ttl = FakeTTL, data = Address}.

-spec addresses([dns:record()]) -> [inet:ip4_address()].
%% @doc Returns a list of IPv4 addresses from the given DNS records.
addresses(Records) ->
  [data(Rec) || Rec <- Records, is_a_record(Rec)].

%% @doc Extracts data from a DNS record.
data(#dns_record{data = Data}) -> Data.
%% @doc Returns true when the argument is an A record.
is_a_record(#dns_record{type = a}) -> true;
is_a_record(_) -> false.
