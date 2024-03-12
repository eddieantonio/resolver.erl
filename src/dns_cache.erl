%%% @doc Cache DNS records, keeping track of their expiry date.
%%%
%%% Currently, DNS records are stored along side with the time that they were
%%% stored. The time is recorded by `erlang:monotonic_time/1', and the time is
%%% stored in seconds so that it can be directly compared to the time stored
%%% in the record's TTL.
%%% @end
-module(dns_cache).

-export([new/0]).
-export([add_records/2, add_records/3]).
-export([get_all_records/2, get_all_records/3]).
-export([expired/1, expired/2]).

-include("include/dns.hrl").


% Types %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type storage() :: #{string() => [cached_record()]}. %% The cache data structure.
%% The keys are the domain name, normalized in lowercase.
%% All records, regardless of type, are currently stored in one giant list per domain.

-type monotonic_time() :: integer(). %% Internal representation of time.
%%
%% We are using `erlang:monotonic_time/1' so that we do not prematurely expire
%% records in the event of a time warp.

-type cached_record() :: {monotonic_time(), dns:record()}. %% An entry in the cache.
%%
%% Each record is stored with the time that it was fetched on this runtime
%% system. Note that the time cannot be compared with other runtime systems.


-type result() :: {hit, nonempty_list(dns:record())} | miss | expired. %% Result of
%% `get_all_records/2,3'.
%%
%% The domain can either have:
%%  1. a cache hit, with at least one, valid, non-expired record
%%  2. a cache hit, but all records are expired
%%  3. or you can a cache miss -- no records are cached for this domain.


% Public API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec new() -> storage().
%% @doc Create an empty cache.
new() -> #{}.

-spec add_records(storage(), [dns:record()]) -> storage().
%% @doc Add new records to the cache.
%% Same as add_records/3 with the current time.
add_records(Cache, Records) ->
  add_records(Cache, Records, right_now()).

-spec add_records(storage(), [dns:record()], monotonic_time()) -> storage().
%% @doc Add new records to the cache.
add_records(Cache, Records, CreatedAt) ->
  lists:foldr(fun (Record, C) ->
                  add_record(C, Record, CreatedAt)
              end, Cache, Records).

-spec get_all_records(storage(), string()) -> {storage(), result()}.
%% @doc Get all records associated this this domain.
%% Same as `get_all_records/3' fetched with the current time.
get_all_records(Cache, Name) ->
  get_all_records(Cache, Name, right_now()).

%% @doc Get all records associated this this domain.
%% Any expired records for the current domain are removed when calling this
%% function.
get_all_records(Cache, Name, When) ->
  NormalizedName = normalize_name(Name),
  case Cache of
    #{NormalizedName := Entries} ->
      get_cached_records(Cache, NormalizedName, Entries, When);
    _ ->
      {Cache, miss}
  end.

%% @doc Returns `true' if a cache entry has an expired record.
%% Same as `expired/2' with the current time.
-spec expired(cached_record()) -> boolean().
expired(Record) ->
  expired(Record, right_now()).

%% @doc Returns `true' if a cache entry has an expired record.
expired({TimeReceived , #dns_record{ttl = Duration}}, TimeRetrieved) ->
  TimeRetrieved > TimeReceived + Duration.


% Internal %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

get_cached_records(Cache, Name, Entries, When) ->
  NewEntries = [E || E <- Entries, not expired(E, When)],
  case NewEntries of
    [] ->
      % Cache hit, but all entries are expired:
      NewCache = maps:remove(Name, Cache),
      Result = expired;

    _ ->
      % Cache hit!
      NewCache = Cache#{Name => NewEntries},
      Result = {hit, records(NewEntries)}
  end,
  {NewCache, Result}.

%% @doc Return just the records from a list of cache entries.
-spec records([cached_record()]) -> [dns:record()].
records(Entries) ->
  [Record || {_, Record} <- Entries].

add_record(Cache, Record, CreatedAt) ->
  #dns_record{name = GrossUglyName} = Record,
  Name = normalize_name(GrossUglyName),
  NormalizedRecord = Record#dns_record{name=Name},
  NewEntry = make_entry(NormalizedRecord, CreatedAt),
  NewEntries = case Cache of
                 % Cache hit. Update existing entries.
                 #{Name := Entries} -> [NewEntry|Entries];
                 % Cache miss: new list!
                 _ -> [NewEntry]
               end,
  Cache#{Name => NewEntries}.

%% @doc Returns a normalized domain name.
normalize_name(Name) ->
  % For now, just lowercase it. There might be more to it than that in the
  % future.
  string:lowercase(Name).

%% @doc Make a cache entry.
-spec make_entry(dns:record(), monotonic_time()) -> cached_record().
make_entry(Record, CreatedAt) ->
  {CreatedAt, Record}.

-spec right_now() -> monotonic_time().
right_now() ->
  erlang:monotonic_time(second).
