%%% @doc DNS data types.
-module(dns).

-export_type([packet/0, question/0, record/0]).
-export_type([record_type/0, class/0, flag/0]).
-export_type([ttl/0, query_id/0]).

-include("src/dns.hrl").


%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


-type packet() :: #{id => query_id(),
                    flags => [dns:flag()],
                    questions => [dns:question()],
                    answers => [dns:record()],
                    authorities => [dns:record()],
                    additionals => [dns:record()]
                   }.  %% A parsed DNS packet.
%% Can be either a query or response (depending on flags).

% See src/dns.hrl for definitions of the following two:
-type question() :: #dns_question{}.
-type record() :: #dns_record{}.


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


-type ttl() :: 0..4294967296.  %% "Time to live" for a DNS record, in seconds.

-type query_id() :: 0..65535. %% A (more-or-less) unique ID for each query
%% and its respective response.
