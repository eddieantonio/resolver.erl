%%% @doc resolver - a DNS resolver.
-module(dns_resolver).

-export([send_query/2, send_query/3, send_query/4]).
-import(lists, [reverse/1]).

%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type u16() :: 0..65535.

-type record_type() :: a | aaaa | cname | ns | soa.  %% DNS record type.
-type class() :: in | cs | ch | hs.
-type dns_flag() :: query
                  | response
                  | opcode()
                  | authoritative_answer
                  | truncation
                  | recursion_desired
                  | recursion_available
                  | {error, response_code() | unknown}.

-type opcode() :: standard_query | inverse_query | status_request.

-type response_code() :: format_error
                       | server_failure
                       | name_error
                       | not_implemented
                       | refused.

-type label_length() :: 1..63. %% Length of a DNS label.
%% A label is an individual components in between the dots of a domain name.
%% Did you know they're limited to a maximum of 63 characters?

-type label() :: {label_length(), string()}.

%% DNS header, for serialization to the wire.
-record(dns_header_out, {id :: u16(),
                         flags = 0 :: u16(),
                         n_questions = 0 :: u16(),
                         n_answers = 0 :: u16(),
                         n_authorities = 0 :: u16(),
                         n_additionals = 0 :: u16()}).

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
  Query = build_query(DomainName, RecordType),
  {ok, Socket} = gen_udp:open(0, [inet, binary, {active, false}]),
  ok = gen_udp:send(Socket, IPAddress, Port, Query),
  Reply = catch gen_udp:recv(Socket, 1024, 30 * 1000),
  gen_udp:close(Socket),
  case Reply of
    {ok, {_IP, _Port, Packet}} -> {ok, dns_parse:packet(Packet)};
    Err -> Err
  end.


%% Serialization %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec build_query(string(), record_type()) -> iolist().
build_query(DomainName, RecordType) ->
  ID = random_id(),
  Flags = proplist_to_flags([recursion_desired]),
  Header = header_to_bytes(#dns_header_out{id = ID,
                                           flags = Flags,
                                           n_questions = 1}),
  Question = question_to_bytes(DomainName, RecordType, in),
  [Header, Question].

-spec proplist_to_flags([dns_flag()]) -> u16().
proplist_to_flags(List) ->
  proplist_to_flags(List, {0}).

proplist_to_flags([], {RD}) ->
  %                    QR   Op   AA   TC   RD    RA   Z    Rcode
  <<Flags:16/big>> = <<0:1, 0:4, 0:1, 0:1, RD:1, 0:1, 0:3, 0:4>>,
  Flags;
proplist_to_flags([recursion_desired|Rest], {_}) ->
  proplist_to_flags(Rest, {1}).

-spec header_to_bytes(#dns_header_out{}) -> <<_:96>>.
header_to_bytes(Header) ->
  #dns_header_out{id = ID,
                  flags = Flags,
                  n_questions = NQuestions,
                  n_answers = NAnswers,
                  n_authorities = NAuthorities,
                  n_additionals = NAdditionals} = Header,
  <<ID:16/big,
    Flags:16/big,
    NQuestions:16/big,
    NAnswers:16/big,
    NAuthorities:16/big,
    NAdditionals:16/big>>.

-spec question_to_bytes(string(), record_type(), class()) -> iolist().
question_to_bytes(Name, RecordType, Class) ->
  EncodedName = encode_dns_name(Name),
  RecordTypeInt = record_type_to_number(RecordType),
  ClassInt = class_to_number(Class),
  [EncodedName, <<RecordTypeInt:16/big, ClassInt:16/big>>].

-spec encode_dns_name(string()) -> iolist().
encode_dns_name(Name) ->
  [[[Length, Label] || {Length, Label} <- labels(Name)], 0].

-spec labels(string()) -> [label()].
labels(Name) ->
  labels(reverse(Name), [], 0, []).

%% labels/4 parses from the end of the string to the beginning.
%%
%% It iterates over each character, prepending it to current label.  When it
%% reaches a ".", it prepends the complete label to the accumulator.
%%
%% e.g.,
%%  labels("example.com")
%%      ---> labels("moc.elpmaxe", "", 0, [])
%%      ...
%%      ---> labels(".elpmaxe", "com", 3, [])
%%      ---> labels("elpmaxe", "", 0, [{3, "com"}])
%%      ---> labels("", "example", 7, [{3, "com"}])
%%      ---> [{7, "example"}, {3, "com"}].
%%
-spec labels(Reversed :: string(),
             Current :: string(),
             Length :: 0 | label_length(),
             Acc :: [label()]) -> [label()].
labels([], [], 0, Acc) ->
    % Edge case: Reached the end, but no current label.
    Acc;
labels([], Current, Length, Acc) ->
    % Parsed entire end of string. Add the last label.
    [{Length, Current}|Acc];
labels([$.|Rest], [], 0, Acc) ->
    % Edge case: empty label -- just skip it.
    labels(Rest, [], 0, Acc);
labels([$.|Rest], Current, Length, Acc) ->
    % Complete label; start the next one.
    labels(Rest, [], 0, [{Length, Current}|Acc]);
labels([Char|Rest], Current, Length, Acc) when Length < 63 ->
    % General case: add a character to the current label.
    labels(Rest, [Char|Current], Length + 1, Acc).


%% DNS data %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec record_type_to_number(record_type()) -> u16().
record_type_to_number(a) -> 1;
record_type_to_number(ns) -> 2;
record_type_to_number(cname) -> 5.

% These functions are sort of pointless.
-spec class_to_number(class()) -> u16().
class_to_number(in) -> 1.

%% Utilities %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec random_id() -> u16().
random_id() ->
  rand:uniform(65536) - 1.

% Run
%   !./get-resolvers.sh -e
% to get the current resolver IP address(es) in Erlang syntax.
-spec current_resolver() -> inet:ip4_address().
current_resolver() -> {10,21,200,25}.
