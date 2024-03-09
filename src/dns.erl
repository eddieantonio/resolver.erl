%%% @doc DNS data types and utilities.
-module(dns).

-export_type([record_type/0, class/0, flag/0]).


%% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type record_type() :: a | aaaa | cname | ns | soa.  %% The type of a
%% "resource record".
%%
%% See [https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2]

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
