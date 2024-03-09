-module(test_dns_query).

-include_lib("eunit/include/eunit.hrl").

% We only really care about querying for A and NS records for now.
a_record_test() ->
  ID = dns_query:random_id(),
  Expected = <<ID:16/big,1,0,0,1,0,0,0,0,0,0, % Header
               7,"example",3,"com",0,0,1,0,1 % Question
             >>,
  Raw = dns_query:build(ID, "example.com", a),
  Expected = iolist_to_binary(Raw).

ns_record_test() ->
  ID = dns_query:random_id(),
  Expected = <<ID:16/big,1,0,0,1,0,0,0,0,0,0, % Header
               7,"example",3,"com",0,0,2,0,1 % Question
             >>,
  Raw = dns_query:build(ID, "example.com", ns),
  Expected = iolist_to_binary(Raw).
