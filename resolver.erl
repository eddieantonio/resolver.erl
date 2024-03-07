%% resolver - DNS resolver.
-module(resolver).

-export([send_query/3, build_query/2, number_to_record_type/1, labels/1]).

-type u16() :: 0..65535.
-type record_type() :: a | cname.
-record(dns_header, {id :: u16(),
                     flags = 0 :: u16(),
                     n_questions = 0 :: u16(),
                     n_answers = 0 :: u16(),
                     n_authorities = 0 :: u16(),
                     n_additionals = 0 :: u16()}).

send_query(IPAddress, DomainName, RecordType) ->
    Query = build_query(DomainName, RecordType),
    {ok, Socket} = gen_udp:open(0, [inet, binary, {active, false}]),
    ok = gen_udp:send(Socket, IPAddress, 53, Query),
    Reply = catch gen_udp:recv(Socket, 1024, 30 * 1000),
    gen_udp:close(Socket),
    Reply.

-spec build_query(string(), record_type()) -> iolist().
build_query(DomainName, RecordType) ->
    ID = random_id(),
    Header = header_to_bytes(#dns_header{id = ID,
                                         n_questions = 1}),
    Question = question_to_bytes(DomainName, RecordType, in),
    [Header, Question].

-spec random_id() -> u16().
random_id() ->
    rand:uniform(65536) - 1.

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

-spec record_type_to_number(record_type()) -> 0..65535.
record_type_to_number(a) -> 1;
record_type_to_number(ns) -> 2;
record_type_to_number(cname) -> 5.

number_to_record_type(1) -> a;
number_to_record_type(2) -> ns;
number_to_record_type(5) -> cname.

class_to_number(in) -> 1.
