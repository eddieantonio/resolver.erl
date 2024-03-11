-module(test_dns_cache).

-include_lib("eunit/include/eunit.hrl").
-include("src/dns.hrl").


check_expired_at_creation_time_test() ->
  Entry = {0, dns_record_with_ttl(3600)},
  false = dns_cache:expired(Entry, 0).

check_expired_at_end_test() ->
  Entry = {0, dns_record_with_ttl(3600)},
  false = dns_cache:expired(Entry, 3600).

check_expired_after_end_test() ->
  Now = 3601,
  Entry = {0, dns_record_with_ttl(3600)},
  true = dns_cache:expired(Entry, Now).

check_expired_false_realistic_test() ->
  Entry = {-576460735, dns_record_with_ttl(3600)},
  false = dns_cache:expired(Entry, -576460706).

check_expired_true_realistic_test() ->
  Entry = {-576460735, dns_record_with_ttl(4)},
  true = dns_cache:expired(Entry, -576460706).


% Utilties %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Create a fake DNS record with the given TTL.
dns_record_with_ttl(TTL) ->
  #dns_record{name="localhost", type=a,
              class=in, ttl=TTL, data ={127, 0, 0, 1}}.
