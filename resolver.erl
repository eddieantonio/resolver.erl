%% resolver - DNS resolver.
-module(resolver).
-export([send_query/2, send_query/3]).
-import(lists, [reverse/1]).

%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type u16() :: 0..65535.
-type u32() :: 0..4294967296.

-type record_type() :: a | aaaa | cname | ns | soa.
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

%% DNS header, for serialization to the wire.
-record(dns_header_out, {id :: u16(),
                         flags = 0 :: u16(),
                         n_questions = 0 :: u16(),
                         n_answers = 0 :: u16(),
                         n_authorities = 0 :: u16(),
                         n_additionals = 0 :: u16()}).

%% DNS header, for use within Erlang.
-record(dns_header, {id :: u16(),
                     flags = 0 :: [dns_flag()],
                     n_questions = 0 :: u16(),
                     n_answers = 0 :: u16(),
                     n_authorities = 0 :: u16(),
                     n_additionals = 0 :: u16()}).

% DNS question, for use within Erlang.
-record(dns_question, {name :: string(),
                       type :: record_type(),
                       class :: class()}).

% DNS record, for use within Erlang.
-record(dns_record, {name :: string(),
                     type :: record_type(),
                     class :: class(),
                     ttl :: u32(),
                     % data depends on the record type.
                     data :: any()}).


%% Public API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Send a DNS query to the current DNS resolver.
%% Same as send_query/2 with the current DNS resolver.
-spec send_query(DomainName :: string(), Type :: record_type()) -> any().
send_query(DomainName, RecordType) ->
  send_query(current_resolver(), DomainName, RecordType).

%% Send a DNS query to the DNS resolver at the given query.
-spec send_query(inet:ip4_address(), string(), record_type()) -> any().
send_query(IPAddress, DomainName, RecordType) ->
  Query = build_query(DomainName, RecordType),
  {ok, Socket} = gen_udp:open(0, [inet, binary, {active, false}]),
  ok = gen_udp:send(Socket, IPAddress, 53, Query),
  Reply = catch gen_udp:recv(Socket, 1024, 30 * 1000),
  gen_udp:close(Socket),
  case Reply of
    {ok, {_IP, _Port, Packet}} -> {ok, parse_dns_packet(Packet)};
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

-type label_length() :: 0..63.
-type label() :: {label_length(), string()}.
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
             Length :: label_length(),
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


%% Parsing/Deserialization %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

parse_dns_packet(Datagram) ->
  <<ID:16/big,
    Flags:16/big,
    NQuestions:16/big,
    NAnswers:16/big,
    NAuthorities:16/big,
    NAdditionals:16/big,
    R0/binary>> = Datagram,
  Props = flags_to_proplist(Flags),
  Header = #dns_header{id=ID, flags=Props, n_questions=NQuestions,
                       n_answers=NAnswers, n_authorities=NAuthorities,
                       n_additionals=NAdditionals},
  {Questions, R1} = parse_questions(R0, NQuestions, Datagram),
  {Answers, R2} = parse_records(R1, NAnswers, Datagram),
  {Authorities, R3} = parse_records(R2, NAuthorities, Datagram),
  {Additionals, <<>>} = parse_records(R3, NAdditionals, Datagram),
  {Header, Questions, Answers, Authorities, Additionals}.


flags_to_proplist(Flags) when is_number(Flags) ->
    flags_to_proplist(<<Flags:16/big>>);
flags_to_proplist(<<QR:1, Opcode:4, AA:1, TC:1, RD:1, RA:1, 0:3, RCode:4>>) ->
    [case QR of
         0 -> query;
         1 -> response
     end,
     case Opcode of
         0 -> standard_query;
         1 -> inverse_query;
         2 -> server_status;
         _ -> unknown_opcode
     end]
    ++ prop_if_nonzero(AA, authoritative_answer)
    ++ prop_if_nonzero(TC, truncation)
    ++ prop_if_nonzero(RD, recursion_desired)
    ++ prop_if_nonzero(RA, recursion_available)
    ++ error_if_nonzero(RCode).

prop_if_nonzero(0, _) -> [];
prop_if_nonzero(1, Prop) -> [Prop].

error_if_nonzero(0) -> [];
error_if_nonzero(N) -> [{error, number_to_response_code(N)}].

number_to_response_code(1) -> format_error;
number_to_response_code(2) -> server_failure;
number_to_response_code(3) -> name_error;
number_to_response_code(4) -> not_implemented;
number_to_response_code(5) -> refused;
number_to_response_code(_) -> unknown.


parse_questions(Bytes, N, Datagram) ->
  parse_questions(Bytes, N, Datagram, []).

parse_questions(Bytes, 0, _, Questions) ->
  {reverse(Questions), Bytes};
parse_questions(Bytes, N, Datagram, Acc) ->
  {Name, Rest} = decode_name(Bytes, Datagram),
  <<Type:16/big, Class:16/big, Remainder/binary>> = Rest,
  Current = #dns_question{name = Name,
                          type = number_to_record_type(Type),
                          class = number_to_class(Class)},
  parse_questions(Remainder, N - 1, Datagram, [Current|Acc]).


-spec parse_records(binary(), non_neg_integer(), binary()) -> {[#dns_record{}], binary()}.
parse_records(Bytes, N, Datagram) ->
  parse_records(Bytes, N, Datagram, []).

parse_records(Bytes, 0, _Datagram, Records) ->
  {reverse(Records), Bytes};
parse_records(Bytes, N, Datagram, Acc) ->
  {Name, Rest} = decode_name(Bytes, Datagram),
  <<Type:16/big, Class:16/big, TTL:32/big, DataLen:16/big, PossiblyData/binary>> = Rest,
  <<Data:DataLen/binary, Remainder/binary>> = PossiblyData,
  RecordType = number_to_record_type(Type),
  ParsedData = parse_record_data(RecordType, Data, Datagram),
  Current = #dns_record{name = Name,
                        type = RecordType,
                        class = number_to_class(Class),
                        ttl = TTL,
                        data = ParsedData},
  parse_records(Remainder, N - 1, Datagram, [Current|Acc]).


parse_record_data(a, <<A, B, C, D>>, _) ->
  {A, B, C, D};
parse_record_data(ns, Data, Packet) ->
  decode_name_discard_data(Data, Packet);
parse_record_data(cname, Data, Packet) ->
  decode_name_discard_data(Data, Packet);
parse_record_data(aaaa, <<A:16/big, B:16/big, C:16/big, D:16/big, E:16/big, F:16/big, G:16/big, H:16/big >>, _) ->
  {A, B, C, D, E, F, G, H};
parse_record_data(_, Binary, _) ->
  {not_parsed, Binary}.


decode_name_discard_data(Data, Packet) ->
  {Name, _} = decode_name(Data, Packet),
  Name.

decode_name(Bytes, Datagram) ->
  {ReversedLabels, Rest} = decode_name(Bytes, Datagram, []),
  Labels = [binary_to_list(Label) || Label <- reverse(ReversedLabels)],
  Name = lists:flatten(lists:join(".", Labels)),
  {Name, Rest}.

decode_name(<<0, Rest/binary>>, _Datagram, Labels)  ->
  {Labels, Rest};
decode_name(<<2#11:2, Offset:14, Rest/binary>>, Datagram, Labels) ->
  EarlierChunk = binary_part_til_end(Datagram, Offset),
  {NewLabels, _} = decode_name(EarlierChunk, Datagram, Labels),
  {NewLabels, Rest};
decode_name(<<Length, Data/binary>>, Datagram, Labels) when Length =< 63 ->
  <<Label:Length/binary, Rest/binary>> = Data,
  decode_name(Rest, Datagram, [Label|Labels]).

binary_part_til_end(Binary, Offset) ->
  Length = max(0, byte_size(Binary) - Offset),
  binary_part(Binary, {Offset, Length}).


%% DNS data %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec record_type_to_number(record_type()) -> u16().
record_type_to_number(a) -> 1;
record_type_to_number(ns) -> 2;
record_type_to_number(cname) -> 5.

-spec number_to_record_type(u16()) -> record_type().
number_to_record_type(1) -> a;
number_to_record_type(2) -> ns;
number_to_record_type(5) -> cname;
number_to_record_type(6) -> soa;
number_to_record_type(28) -> aaaa.

% These functions are sort of pointless.
-spec class_to_number(class()) -> u16().
class_to_number(in) -> 1.

-spec number_to_class(u16()) -> class().
number_to_class(1) -> in;
number_to_class(2) -> cs;
number_to_class(3) -> ch;
number_to_class(4) -> hs.


%% Utilities %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec random_id() -> u16().
random_id() ->
  rand:uniform(65536) - 1.

% Run
%   !./get-resolvers.sh -e
% to get the current resolver IP address(es) in Erlang syntax.
-spec current_resolver() -> inet:ip4_address().
current_resolver() -> {162,252,172,57}.
