%%% @doc Defines Erlang records for DNS questions and records.
%%%
%%% Data types for these records are intended for use within Erlang. To parse
%%% and serialize the records, see the respective modules.

-record(dns_question, {name :: string(),
                       type :: dns:record_type(),
                       class :: dns:class()}).

-record(dns_record, {name :: string(),
                     type :: dns:record_type(),
                     class :: dns:class(),
                     ttl :: dns:ttl(),
                     % Data depends on the record type.
                     data :: any()}).
