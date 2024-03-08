%% resolver - DNS resolver.
%%
-module(resolver).
-export([send_query/2, send_query/3]).


%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type u16() :: 0..65535.
-type u32() :: 0..4294967296.

-type record_type() :: a | aaaa | cname | ns.
-type class() :: in | cs | ch | hs.

%% DNS header, for serialization and deserialization.
-record(dns_header, {id :: u16(),
                     flags = 0 :: u16(),
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

send_query(DomainName, RecordType) ->
    send_query(current_resolver(), DomainName, RecordType).
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

% Flags:
-define(RECURSION_DESIRED, 1 bsl 8).

-spec build_query(string(), record_type()) -> iolist().
build_query(DomainName, RecordType) ->
    ID = random_id(),
    Header = header_to_bytes(#dns_header{id = ID,
                                         flags = ?RECURSION_DESIRED,
                                         n_questions = 1}),
    Question = question_to_bytes(DomainName, RecordType, in),
    [Header, Question].

-spec header_to_bytes(#dns_header{}) -> <<_:96>>.
header_to_bytes(#dns_header{id = ID,
                            flags = Flags,
                            n_questions = NQuestions,
                            n_answers = NAnswers,
                            n_authorities = NAuthorities,
                            n_additionals = NAdditionals}) ->
    <<ID:16/big,
      Flags:16/big,
      NQuestions:16/big,
      NAnswers:16/big,
      NAuthorities:16/big,
      NAdditionals:16/big>>.

question_to_bytes(Name, RecordType, Class) when is_list(Name) ->
    question_to_bytes({encoded, encode_dns_name(Name)}, RecordType, Class);
question_to_bytes({encoded, EncodedName}, RecordType, Class) ->
    RecordTypeInt = record_type_to_number(RecordType),
    ClassInt = class_to_number(Class),
    [EncodedName,
      <<RecordTypeInt:16/big,
        ClassInt:16/big>>].

-spec encode_dns_name(string()) -> iolist().
encode_dns_name(Name) ->
    [[[Length, Label] || {Length, Label} <- labels(Name)], 0].

-type label_length() :: 0..63.
-type label() :: {label_length(), string()}.
-spec labels(string()) -> [label()].
labels(Name) ->
    labels(lists:reverse(Name), [], 0, []).

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
    Header = #dns_header{id=ID, flags=Flags, n_questions=NQuestions,
                         n_answers=NAnswers, n_authorities=NAuthorities,
                         n_additionals=NAdditionals},
    {Questions, R1} = parse_questions(R0, NQuestions, Datagram),
    {Answers, R2} = parse_records(R1, NAnswers, Datagram),
    {Authorities, R3} = parse_records(R2, NAuthorities, Datagram),
    {Additionals, <<>>} = parse_records(R3, NAdditionals, Datagram),
    {Header, Questions, Answers, Authorities, Additionals}.


parse_questions(Bytes, N, Datagram) ->
    parse_questions(Bytes, N, Datagram, []).

parse_questions(Bytes, 0, _, Questions) ->
    {Questions, Bytes};
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
    {Records, Bytes};
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
  {A, B, C, D, E, F, G, H}.

decode_name_discard_data(Data, Packet) ->
  {Name, _} = decode_name(Data, Packet),
  Name.

decode_name(Bytes, Datagram) ->
  {ReversedLabels, Rest} = decode_name(Bytes, Datagram, []),
  Labels = [binary_to_list(Label) || Label <- lists:reverse(ReversedLabels)],
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
