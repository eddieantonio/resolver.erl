-module(test_dns_upstream).

-include_lib("eunit/include/eunit.hrl").

% Just check that it returns any number of resolvers.
from_etc_test() ->
  Resolvers = dns_upstream:from_etc(),
  ?assert(length(Resolvers) > 0).
