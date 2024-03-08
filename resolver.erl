%% resolver - DNS resolver.
-module(resolver).

-export([send_query/2, send_query/3, build_query/2, number_to_record_type/1,
         labels/1, test_case/0, parse_dns_packet/1]).

-type u16() :: 0..65535.
-type u32() :: 0..4294967296.

-type record_type() :: a | aaaa | cname | ns.
-type class() :: in | cs | ch | hs.

-record(dns_header, {id :: u16(),
                     flags = 0 :: u16(),
                     n_questions = 0 :: u16(),
                     n_answers = 0 :: u16(),
                     n_authorities = 0 :: u16(),
                     n_additionals = 0 :: u16()}).

-record(dns_question, {name :: string(),
                       type :: record_type(),
                       class :: class()}).
-record(dns_record, {name :: string(),
                     type :: record_type(),
                     class :: class(),
                     ttl :: u32(),
                     data :: binary()}).

send_query(DomainName, RecordType) ->
    send_query(current_resolver(), DomainName, RecordType).
send_query(IPAddress, DomainName, RecordType) ->
    Query = build_query(DomainName, RecordType),
    {ok, Socket} = gen_udp:open(0, [inet, binary, {active, false}]),
    ok = gen_udp:send(Socket, IPAddress, 53, Query),
    Reply = catch gen_udp:recv(Socket, 1024, 30 * 1000),
    gen_udp:close(Socket),
    case Reply of
        {ok, Packet} -> {ok, parse_dns_packet(Packet)};
        Err -> Err
    end.

%% Serialization %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec build_query(string(), record_type()) -> iolist().
build_query(DomainName, RecordType) ->
    ID = random_id(),
    Header = header_to_bytes(#dns_header{id = ID,
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
    {Questions, R1} = parse_questions(R0, NQuestions),
    {Answers, R2} = parse_records(R1, NAnswers, Datagram),
    {Authorities, R3} = parse_records(R2, NAuthorities, Datagram),
    {Additionals, <<>>} = parse_records(R3, NAdditionals, Datagram),
    {Header, Questions, Answers, Authorities, Additionals}.


parse_questions(Bytes, N) ->
    parse_questions(Bytes, N, []).

parse_questions(Bytes, 0, Questions) ->
    {Questions, Bytes};
parse_questions(Bytes, N, Acc) ->
    {Name, Rest} = decode_name_simple(Bytes),
    <<Type:16/big, Class:16/big, Remainder/binary>> = Rest,
    Current = #dns_question{name = Name,
                            type = number_to_record_type(Type),
                            class = number_to_class(Class)},
    parse_questions(Remainder, N - 1, [Current|Acc]).


-spec parse_records(binary(), non_neg_integer(), binary()) -> {#dns_record{}, binary()}.
parse_records(Bytes, N, Datagram) ->
    parse_records(Bytes, N, Datagram, []).
parse_records(Bytes, 0, _Datagram, Records) ->
    {Records, Bytes};
parse_records(Bytes, N, Datagram, Acc) ->
    {Name, Rest} = decode_name(Bytes, Datagram),
    <<Type:16/big, Class:16/big, TTL:32/big, DataLen:16/big, PossiblyData/binary>> = Rest,
    <<Data:DataLen/binary, Remainder/binary>> = PossiblyData,
    Current = #dns_record{name = Name,
                          type = number_to_record_type(Type),
                          class = number_to_class(Class),
                          ttl = TTL,
                          data = Data},
    parse_records(Remainder, N - 1, Datagram, [Current|Acc]).


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

decode_name_simple(Bytes) ->
    {ReversedLabels, Rest} = decode_name_simple(Bytes, []),
    Name = lists:flatten(lists:join(".", lists:reverse(ReversedLabels))),
    {Name, Rest}.

decode_name_simple(<<0, Rest/binary>>, Acc) ->
    {[binary_to_list(Label) || Label <- Acc], Rest};
decode_name_simple(<<Length, Data/binary>>, Acc) when Length =< 63 ->
    <<Label:Length/binary, Rest/binary>> = Data,
    decode_name_simple(Rest, [Label|Acc]).


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
%class_to_number(cs) -> 2;
%class_to_number(ch) -> 3;
%class_to_number(hs) -> 4.
-spec number_to_class(u16()) -> class().
number_to_class(1) -> in;
number_to_class(2) -> cs;
number_to_class(3) -> ch;
number_to_class(4) -> hs.


%% Utilities %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec random_id() -> u16().
random_id() ->
    rand:uniform(65536) - 1.

current_resolver() -> {162,252,172,57}.

test_case() -> <<63,156,128,128,0,1,0,1,0,13,0,14,7,101,120,97,109,112,108,101,3,99,111,109,0,
  0,1,0,1,192,12,0,1,0,1,0,0,7,81,0,4,93,184,216,34,192,20,0,2,0,1,0,0,4,122,0,
  20,1,100,12,103,116,108,100,45,115,101,114,118,101,114,115,3,110,101,116,0,
  192,20,0,2,0,1,0,0,4,122,0,4,1,105,192,59,192,20,0,2,0,1,0,0,4,122,0,4,1,108,
  192,59,192,20,0,2,0,1,0,0,4,122,0,4,1,107,192,59,192,20,0,2,0,1,0,0,4,122,0,
  4,1,98,192,59,192,20,0,2,0,1,0,0,4,122,0,4,1,101,192,59,192,20,0,2,0,1,0,0,4,
  122,0,4,1,97,192,59,192,20,0,2,0,1,0,0,4,122,0,4,1,102,192,59,192,20,0,2,0,1,
  0,0,4,122,0,4,1,103,192,59,192,20,0,2,0,1,0,0,4,122,0,4,1,109,192,59,192,20,
  0,2,0,1,0,0,4,122,0,4,1,99,192,59,192,20,0,2,0,1,0,0,4,122,0,4,1,106,192,59,
  192,20,0,2,0,1,0,0,4,122,0,4,1,104,192,59,192,169,0,1,0,1,0,0,4,122,0,4,192,
  5,6,30,192,137,0,1,0,1,0,0,4,122,0,4,192,33,14,30,192,233,0,1,0,1,0,0,4,122,
  0,4,192,26,92,30,192,57,0,1,0,1,0,0,4,122,0,4,192,31,80,30,192,153,0,1,0,1,0,
  0,4,122,0,4,192,12,94,30,192,185,0,1,0,1,0,0,4,122,0,4,192,35,51,30,192,201,
  0,1,0,1,0,0,4,122,0,4,192,42,93,30,193,9,0,1,0,1,0,0,4,122,0,4,192,54,112,30,
  192,89,0,1,0,1,0,0,4,122,0,4,192,43,172,30,192,249,0,1,0,1,0,0,4,122,0,4,192,
  48,79,30,192,121,0,1,0,1,0,0,4,122,0,4,192,52,178,30,192,105,0,1,0,1,0,0,4,
  122,0,4,192,41,162,30,192,217,0,1,0,1,0,0,4,122,0,4,192,55,83,30,192,169,0,
  28,0,1,0,0,4,122,0,16,32,1,5,3,168,62,0,0,0,0,0,0,0,2,0,48>>.
