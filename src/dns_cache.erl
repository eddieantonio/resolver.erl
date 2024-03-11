-module(dns_cache).

-export([expired/1, expired/2]).

-include("src/dns.hrl").

-type cached_record() :: {monotonic_time(), dns:record()}.
-type monotonic_time() :: integer().

-spec expired(cached_record()) -> boolean().
expired(Record) ->
  expired(Record, right_now()).

expired({Received , #dns_record{ttl = Duration}}, When) ->
  When > Received + Duration.

right_now() ->
  erlang:monotonic_time(second).
