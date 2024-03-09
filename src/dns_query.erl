%%% @doc Build a DNS query.
-module(dns_query).

-export([build/2, build/3, random_id/0]).


%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type u16() :: 0..65535.

-type label() :: {label_length(), string()}.

-type label_length() :: 1..63. %% Length of a DNS label.
%% A label is the thing between the dots of a domain name.
%% Did you know that they're limited to a maximum of 63 characters?

%% DNS header, for serialization to the wire.
-record(dns_header_out, {id :: u16(),
                         flags = 0 :: u16(),
                         n_questions = 0 :: u16(),
                         n_answers = 0 :: u16(),
                         n_authorities = 0 :: u16(),
                         n_additionals = 0 :: u16()}).


%% Exports %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec build(DomainName :: string(), RecordType:: dns:record_type()) -> iodata().
%% @doc Build a DNS query to request records of the given type using a
%% random ID.
%%
%% Same as {@link build/2. <code>build(dns_query:random_id(), DomainName, RecordType)</code>}.
build(DomainName, RecordType) ->
  build(random_id(), DomainName, RecordType).

-spec build(ID :: u16(), DomainName :: string(), RecordType :: dns:record_type()) -> iodata().
%% @doc Build a DNS query to request records of the given type with the given ID.
%%
%% This function only builds the query; it does not actually send a query to
%% any resolvers.
build(ID, DomainName, RecordType) ->
  Flags = proplist_to_flags([recursion_desired]),
  Header = header_to_bytes(#dns_header_out{id = ID,
                                           flags = Flags,
                                           n_questions = 1}),
  Question = question_to_bytes(DomainName, RecordType, in),
  [Header, Question].

-spec random_id() -> u16().
%% @doc Return an random ID, suitable for a DNS query.
random_id() ->
  rand:uniform(65536) - 1.


%% Internal %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec proplist_to_flags([dns:flag()]) -> u16().
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

-spec question_to_bytes(string(), dns:record_type(), dns:class()) -> iolist().
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

-spec record_type_to_number(dns:record_type()) -> u16().
record_type_to_number(a) -> 1;
record_type_to_number(ns) -> 2;
record_type_to_number(cname) -> 5.

% These functions are sort of pointless.
-spec class_to_number(dns:class()) -> u16().
class_to_number(in) -> 1.
