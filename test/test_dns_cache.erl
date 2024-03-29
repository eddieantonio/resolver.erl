-module(test_dns_cache).

-include_lib("eunit/include/eunit.hrl").
-include("include/dns.hrl").


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

cache_fetch_from_empty_test() ->
  Empty = dns_cache:new(),
  Name = "not.important",
  {Empty, miss} = dns_cache:get_all_records(Empty, Name, 0).

cache_simple_record_test() ->
  Empty = dns_cache:new(),
  InsertTime = 0,
  Record = dns_record_with_ttl(half_hour()),
  Name = name(Record),
  C2 = dns_cache:add_records(Empty, [Record], InsertTime),

  % About a minute later...
  FetchTime = rand:uniform(60),
  {_, {hit, [Record]}} = dns_cache:get_all_records(C2, Name, FetchTime).

cache_fetch_expired_record_test() ->
  Empty = dns_cache:new(),
  InsertTime = 0,
  Record = dns_record_with_ttl(half_hour()),
  Name = name(Record),
  C2 = dns_cache:add_records(Empty, [Record], InsertTime),

  % Just after the expiration time...
  FetchTime = half_hour() + 1,
  {Empty, miss} = dns_cache:get_all_records(C2, Name, FetchTime).

cache_inconsistent_names_test() ->
  Empty = dns_cache:new(),
  InsertTime = 0,
  InsertName = "Localhost",
  Record = dns_record_with_ttl(InsertName, half_hour()),
  C2 = dns_cache:add_records(Empty, [Record], InsertTime),

  % Fetch it right after:
  FetchTime = 1,
  FetchName = "LOCALHOST",
  {C2, {hit, [Result]}} = dns_cache:get_all_records(C2, FetchName, FetchTime),
  "localhost" = name(Result).

% Get a cached A record. This is the typical operation of the cache.
get_cached_a_records_test() ->
  Empty = dns_cache:new(),
  InsertTime = 0,
  Name = "localhost",
  Record = dns_record_with_ttl(Name, half_hour()),
  C1 = dns_cache:add_records(Empty, [Record], InsertTime),

  % Fetch it right after:
  FetchTime = 1,
  {C1, {hit, [Result]}} = dns_cache:get_records(C1, Name, a, FetchTime),
  "localhost" = name(Result).

% Cache miss on an A record, but there's still a NS record in the cache.
% This means that the resolver can still fetch the NS record later.
get_cached_cname_records_test() ->
  Empty = dns_cache:new(),
  InsertTime = 0,
  Name = "localhost",
  Nameserver = "ns.local",
  ARecord = dns_record_with_ttl(Name, half_hour()),
  NSRecord = #dns_record{name=Name, type=ns, class=in, ttl=one_day(), data="ns.local"},
  NameserverRecord = dns_record_with_ttl(Nameserver, one_day()),
  C1 = dns_cache:add_records(Empty, [ARecord, NSRecord, NameserverRecord], InsertTime),

  % Try to fetch the A record after it has expired
  FetchTime = half_hour() + 1,
  {C2, miss} = dns_cache:get_records(C1, Name, a, FetchTime),

  % Okay, try to fetch the NS record then...
  {C2, {hit, [NSRecord]}} = dns_cache:get_records(C2, Name, ns, FetchTime),

  % Now fetch the nameserver's A record:
  {C2, {hit, [NameserverRecord]}} = dns_cache:get_records(C2, Nameserver, a, FetchTime).


% Utilties %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% @doc Create a fake DNS record with the given TTL and optional name.
dns_record_with_ttl(TTL) ->
  dns_record_with_ttl("localhost", TTL).
dns_record_with_ttl(Name, TTL) ->
  #dns_record{name=Name, type=a,
              class=in, ttl=TTL, data ={127, 0, 0, 1}}.

name(#dns_record{name = Name}) -> Name.
half_hour() -> 30 * 60.
one_day() -> 24 * 60 * 60.
