-module(dns_server).
-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

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
  Name = get_name(Question),
  {ok, Addresses} = resolve(Name),
  Answers = [{dns_record, Name, a, in, 3600, A} || A <- Addresses],
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

get_name({dns_question, Name, _, _}) -> Name.

%% @doc Returns a list of IPv4 addresses from the given DNS records.
addresses(Records) ->
  [data(Rec) || Rec <- Records, is_a_record(Rec)].

%% @doc Extracts data from a DNS record.
data({dns_record, _Name, _Type, _Class, _TTL, Data}) -> Data.
%% @doc Returns true when the argument is an A record.
is_a_record({dns_record, _Name, a, _Class, _TTL, _Data}) -> true;
is_a_record(_) -> false.
