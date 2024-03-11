%%% @doc DNS data types.
-module(dns).

-export_type([record_type/0, class/0, flag/0]).
-export_type([u32/0]).
-export_type([packet/0, question/0, record/0]).


%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type record_type() :: a
                     | aaaa
                     | cname
                     | ns
                     | opt
                     | soa.  %% The type of a "resource record".
%%
%% See [https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2]
%% and [https://en.wikipedia.org/wiki/List_of_DNS_record_types]

-type class() :: in | cs | ch | hs. %% Record or query class.
%% In practice, only the IN (Internet) class is used.
%%
%% See [https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4]

-type flag() :: query
              | response
              | opcode()
              | authoritative_answer
              | truncation
              | recursion_desired
              | recursion_available
              | {error, response_code() | unknown}. %% Flags in DNS headers.
%%
%% See [https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1]

-type opcode() :: standard_query | inverse_query | status_request.

-type response_code() :: format_error
                       | server_failure
                       | name_error
                       | not_implemented
                       | refused. %% Error codes

-record(dns_question, {name :: string(),
                       type :: dns:record_type(),
                       class :: dns:class()}).  %% DNS question, for use within Erlang.
-type question() :: #dns_question{}.


-record(dns_record, {name :: string(),
                     type :: dns:record_type(),
                     class :: dns:class(),
                     ttl :: u32(),
                     % Data depends on the record type.
                     data :: any()}).  %% DNS record, for use within Erlang.
-type record() :: #dns_record{}.


-type packet() :: #{id => u16(),
                    flags => [dns:flag()],
                    questions => [dns:question()],
                    answers => [dns:record()],
                    authorities => [dns:record()],
                    additionals => [dns:record()]
                   }.  %% A parsed DNS packet.
%% Can be either query or response (depending on flags).


% Internal %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% TODO: rename this to query_id().
-type u16() :: 0..65535. %% Unsigned 16 bit integer.
% TODO: rename this to ttl()
-type u32() :: 0..4294967296.  %% Unsigned 32 bit integer.
