%%% @doc Parse a DNS packet.
-module(dns_parse).

-export([packet/1]).

%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type u16() :: 0..65535.

-record(dns_question, {name :: string(),
                       type :: dns:record_type(),
                       class :: dns:class()}).  %% DNS question, for use within Erlang.

-record(dns_record, {name :: string(),
                     type :: dns:record_type(),
                     class :: dns:class(),
                     ttl :: dns:ttl(),
                     % Data depends on the record type.
                     data :: any()}).  %% DNS record, for use within Erlang.


% Public API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec packet(Packet :: binary()) -> dns:packet() | {error, invalid_offset}.
%% @doc Parses an entire DNS datagram.
%%
%% Produces a map of all the data contained within.
packet(Packet) ->
  try parse_packet(Packet)
  catch
    % Parsing might intentionally throw an error, so return it.
    throw:Error -> Error
  end.


% Internal %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

parse_packet(Packet) ->
  <<ID:16/big,
    Flags:16/big,
    NQuestions:16/big,
    NAnswers:16/big,
    NAuthorities:16/big,
    NAdditionals:16/big,
    R0/binary>> = Packet,
  Props = flags_to_proplist(Flags),
  {Questions, R1} = parse_questions(R0, NQuestions, Packet),
  {Answers, R2} = parse_records(R1, NAnswers, Packet),
  {Authorities, R3} = parse_records(R2, NAuthorities, Packet),
  {Additionals, <<>>} = parse_records(R3, NAdditionals, Packet),
  #{id => ID,
    flags => Props,
    questions => Questions,
    answers => Answers,
    authorities => Authorities,
    additionals => Additionals}.


flags_to_proplist(Flags) when is_number(Flags) ->
    flags_to_proplist(<<Flags:16/big>>);
flags_to_proplist(<<QR:1, Opcode:4, AA:1, TC:1, RD:1, RA:1, _:3, RCode:4>>) ->
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


-spec parse_questions(binary(), non_neg_integer(), binary()) -> {[dns:question()], binary()}.
parse_questions(Bytes, N, Datagram) ->
  parse_questions(Bytes, N, Datagram, []).

parse_questions(Bytes, 0, _, Questions) ->
  {lists:reverse(Questions), Bytes};
parse_questions(Bytes, N, Datagram, Acc) ->
  {Name, Rest} = decode_name(Bytes, Datagram),
  <<Type:16/big, Class:16/big, Remainder/binary>> = Rest,
  Current = #dns_question{name = Name,
                          type = number_to_record_type(Type),
                          class = number_to_class(Class)},
  parse_questions(Remainder, N - 1, Datagram, [Current|Acc]).


-spec parse_records(binary(), non_neg_integer(), binary()) -> {[dns:record()], binary()}.
parse_records(Bytes, N, Datagram) ->
  parse_records(Bytes, N, Datagram, []).

parse_records(Bytes, 0, _Datagram, Records) ->
  {lists:reverse(Records), Bytes};
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


parse_record_data(a, <<A, B, C, D>>, _) -> {A, B, C, D};
parse_record_data(ns, Data, Packet) -> decode_name_and_ignore_remainder(Data, Packet);
parse_record_data(cname, Data, Packet) -> decode_name_and_ignore_remainder(Data, Packet);
parse_record_data(aaaa, Data, _) -> decode_ip6_address(Data);
% Do not crash -- leave rest of the record unparsed:
parse_record_data(_, Binary, _) -> {not_parsed, Binary}.

decode_name_and_ignore_remainder(Data, Packet) ->
  {Name, _} = decode_name(Data, Packet),
  Name.

decode_name(Bytes, Datagram) ->
  {ReversedLabels, Rest} = decode_name(Bytes, Datagram, [], []),
  Labels = [binary_to_list(Label) || Label <- lists:reverse(ReversedLabels)],
  Name = lists:flatten(lists:join(".", Labels)),
  {Name, Rest}.

decode_name(<<0, Rest/binary>>, _Datagram, Labels, _Offsets)  ->
  {Labels, Rest};
decode_name(<<2#11:2, Offset:14, Rest/binary>>, Datagram, Labels, Offsets) ->
  case lists:member(Offset, Offsets) of
    % Infinite loop detected:
    true -> throw({error, invalid_offset});
    _ -> ok
  end,
  EarlierChunk = binary_part_until_end(Datagram, Offset),
  {NewLabels, _} = decode_name(EarlierChunk, Datagram, Labels, [Offset|Offsets]),
  {NewLabels, Rest};
decode_name(<<Length, Data/binary>>, Datagram, Labels, Offsets) when Length =< 63 ->
  <<Label:Length/binary, Rest/binary>> = Data,
  decode_name(Rest, Datagram, [Label|Labels], Offsets).

%% Extract this function because the pattern match is too big for one line.
decode_ip6_address(<<A:16/big, B:16/big, C:16/big, D:16/big, E:16/big, F:16/big, G:16/big, H:16/big >>) ->
  {A, B, C, D, E, F, G, H}.


%% @doc Returns a suffix of the binary, starting at the given offset.
%%
%% Equivalent to the Python expression <code>binary[offset:]</code>.
binary_part_until_end(Binary, Offset) ->
  Length = max(0, byte_size(Binary) - Offset),
  binary_part(Binary, {Offset, Length}).

-spec number_to_record_type(u16()) -> dns:record_type().
number_to_record_type(1) -> a;
number_to_record_type(2) -> ns;
number_to_record_type(5) -> cname;
number_to_record_type(6) -> soa;
number_to_record_type(28) -> aaaa;
number_to_record_type(41) -> opt.

-spec number_to_class(u16()) -> dns:class().
number_to_class(1) -> in;
number_to_class(2) -> cs;
number_to_class(3) -> ch;
number_to_class(4) -> hs;
number_to_class(Number) ->
  {unknown_class, Number}.
