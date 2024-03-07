%% resolver - DNS resolver.
-module(resolver).

-export([send_query/3, build_query/2, number_to_record_type/1]).

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
    [[[Length, Component] || {Length, Component} <- to_components(Name)], 0].

to_components(Name) ->
    lists:reverse(to_components(Name, [], [])).

% Parsed the end, no trailing dot.
to_components([], [], Acc) ->
    Acc;
to_components([], Current, Acc) ->
    [as_component(Current)|Acc];
to_components([$.|Rest], Current, Acc) ->
    to_components(Rest, [], [as_component(Current)|Acc]);
to_components([Char|Rest], Current, Acc) ->
    to_components(Rest, [Char|Current], Acc).

-spec as_component(string()) -> {non_neg_integer(), string()}.
as_component(ReversedComponent) ->
    {length(ReversedComponent), lists:reverse(ReversedComponent)}.

-spec record_type_to_number(record_type()) -> 0..65535.
record_type_to_number(a) -> 1;
record_type_to_number(ns) -> 2;
record_type_to_number(cname) -> 5.

number_to_record_type(1) -> a;
number_to_record_type(2) -> ns;
number_to_record_type(5) -> cname.

class_to_number(in) -> 1.
