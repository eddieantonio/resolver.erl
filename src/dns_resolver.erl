%%% @doc A DNS resolver.
-module(dns_resolver).

-export([send_query/2, send_query/3, send_query/4]).


%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type u16() :: 0..65535.
-type record_type() :: a | aaaa | cname | ns | soa.  %% DNS record type.

%% Public API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec send_query(DomainName :: string(), Type :: record_type()) -> any().
%% @doc Send a DNS query to the current DNS resolver.
%%
%% Same as send_query/3 with the current DNS resolver.
send_query(DomainName, RecordType) ->
  send_query(current_resolver(), DomainName, RecordType).

-spec send_query(inet:ip4_address(), string(), record_type()) -> any().
%% @doc Send a query to the given DNS resolver at the default port.
%%
%% Same as send_query/4 with port 53 (default DNS port).
send_query(IPAddress, DomainName, RecordType) ->
  send_query(IPAddress, 53, DomainName, RecordType).

-spec send_query(inet:ip4_address(), u16(), string(), record_type()) -> dns_parse:dns_packet().
%% @doc Send a DNS query to the given address and port.
%%
%% Builds a question for the given domain name and record type,
%% and sends it to the DNS resolver with the given IP address and port.
%% Returns a parsed representation of the resolver's response.
send_query(IPAddress, Port, DomainName, RecordType) ->
  Query = dns_query:build(DomainName, RecordType),
  {ok, Socket} = gen_udp:open(0, [inet, binary, {active, false}]),
  ok = gen_udp:send(Socket, IPAddress, Port, Query),
  Reply = catch gen_udp:recv(Socket, 1024, 30 * 1000),
  gen_udp:close(Socket),
  case Reply of
    {ok, {_IP, _Port, Packet}} -> {ok, dns_parse:packet(Packet)};
    Err -> Err
  end.


%% Utilities %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec current_resolver() -> inet:ip4_address().
%% @doc Gets the first resolver configured in /etc/resolv.conf
current_resolver() ->
  [Resolver|_] = dns_upstream:from_etc(),
  Resolver.
