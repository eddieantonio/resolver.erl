-module(dns_server).
-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-include("src/dns.hrl").

-define(NAME, ?MODULE).
-record(state, {socket}).

% Init %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_link(Port) ->
  gen_server:start_link({local, ?NAME}, ?MODULE, [Port], [{debug, [trace]}]).


% gen_server callbacks %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init([Port]) ->
  IP = {127,0,0,1},
  {ok, Socket} = gen_udp:open(Port, [binary, {ip, IP}, {active, true}]),
  io:format("[~p] Listening on ~w:~p~n", [?NAME, IP, Port]),
  {ok, #state{socket=Socket}}.

handle_call(_Message, _From, State) ->
  {noreply, State}.

handle_cast(_, State) ->
  {noreply, State}.

% DNS Query.
handle_info({udp, Socket, Host, Port, Datagram}, State) ->
  Packet = dns_parse:packet(Datagram),
  #{id := ID, questions := [Question|_]} = Packet,
  Name = name(Question),
  {ok, Addresses} = resolve(Name),
  Answers = [make_fake_record(Name, A) || A <- Addresses],
  Response = dns_query:build_response(ID, [Question], Answers),
  ok = gen_udp:send(Socket, Host, Port, Response),
  {noreply, State}.

terminate(_, #state{socket=Socket}) ->
  ok = gen_udp:close(Socket),
  ok.

% Internal %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

resolve(Name) ->
  {ok, #{answers := Answers}} = dns_resolver:send_query(Name, a),
  case addresses(Answers) of
    [] -> {error, nxdomain};
    Addresses -> {ok, Addresses}
  end.

%% @doc Return the domain name from a question.
name(#dns_question{name = Name}) -> Name.

%% @doc I haven't implemented this correctly, so this will have to do for now.
make_fake_record(Name, Address) ->
  FakeTTL = 3600, % Just make something up.
  #dns_record{name = Name, type = a, class = in,
              ttl = FakeTTL, data = Address}.

%% @doc Returns a list of IPv4 addresses from the given DNS records.
addresses(Records) ->
  [data(Rec) || Rec <- Records, is_a_record(Rec)].

%% @doc Extracts data from a DNS record.
data(#dns_record{data = Data}) -> Data.
%% @doc Returns true when the argument is an A record.
is_a_record(#dns_record{type = a}) -> true;
is_a_record(_) -> false.
