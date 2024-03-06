-module(resolver).

-export([send_query/3, number_to_record_type/1]).

send_query(IPAddress, DomainName, RecordType) ->
    Query = build_query(DomainName, RecordType),
    {ok, Socket} = gen_udp:open(0, [inet, binary, {active, false}]),
    gen_udp:send(Socket, IPAddress, 53, Query),
    Reply = gen_udp:recv(Socket, 1024, 30 * 1000),
    gen_udp:close(Socket),
    Reply.

build_query(DomainName, RecordType) ->
    ID = random_id(),
    Header = header_to_bytes(#{id => ID,
                               flags => 0,
                               n_questions => 1}),
    Question = question_to_bytes(DomainName, RecordType, in),
    [Header, Question].

random_id() ->
    rand:uniform(65536) - 1.

header_to_bytes(Header) ->
    #{id := ID} = Header,
    header_to_bytes(ID,
                    maps:get(flags, Header, 0),
                    maps:get(n_questions, Header, 0),
                    maps:get(n_answers, Header, 0),
                    maps:get(n_authorities, Header, 0),
                    maps:get(n_additionals, Header, 0)).
header_to_bytes(ID, Flags, NQuestions, NAnswers, NAuthorities, NAdditionals) ->
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

encode_dns_name(Name) ->
    [[<<Length:8, Component/binary>> || {Length, Component} <- to_components(Name)], 0].

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

as_component(ReversedComponent) ->
    {length(ReversedComponent), list_to_binary(lists:reverse(ReversedComponent))}.

record_type_to_number(a) -> 1;
record_type_to_number(ns) -> 2;
record_type_to_number(cname) -> 5.

number_to_record_type(1) -> a;
number_to_record_type(2) -> ns;
number_to_record_type(5) -> cname.

class_to_number(in) -> 1.
