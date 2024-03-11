-module(dns_cache).

-export([new/0]).
-export([add_records/2, add_records/3]).
-export([get_all_records/2, get_all_records/3]).
-export([expired/1, expired/2]).

-include("include/dns.hrl").

-type storage() :: #{string() => [cached_record()]}.

-type cached_record() :: {monotonic_time(), dns:record()}.
-type monotonic_time() :: integer().

%% @doc create an empty cache
-spec new() -> storage().
new() ->
  #{}.

-spec add_records(storage(), [dns:record()]) -> storage().
%% @doc Add new records to the cache.
%% Same as add_records/3 with the current time.
add_records(Cache, Records) ->
  add_records(Cache, Records, right_now()).

-spec add_records(storage(), [dns:record()], monotonic_time()) -> storage().
add_records(Cache, Records, CreatedAt) ->
  lists:foldr(fun (Record, C) ->
                  add_record(C, Record, CreatedAt)
              end, Cache, Records).

% Hmmm...
% Might want a return like
% {Status, NewCache, Result}
%   {ok, #{}, [Record]}
%   {ok, #{}, [Record]}
%
% or:
%
% {NewCache, Result}
% where Result :: {hit, Records} | miss | expired.
%   {#{...}, {hit, [Record]}}
%   {#{...}, miss}
%   {#{...}, expired}
%
% I prefer the latter.
-type result() :: {hit, [dns:record()]} | miss | expired.
-spec get_all_records(storage(), string()) -> {storage(), result()}.
get_all_records(Cache, Name) ->
  get_all_records(Cache, Name, right_now()).

get_all_records(Cache, Name, When) ->
  NormalizedName = normalize_name(Name),
  case Cache of
    #{NormalizedName := Entries} ->
      get_cached_records(Cache, NormalizedName, Entries, When);
    _ ->
      {Cache, miss}
  end.

get_cached_records(Cache, Name, Entries, When) ->
  NewEntries = [E || E <- Entries, not expired(E, When)],
  case NewEntries of
    [] -> NewCache = maps:remove(Name, Cache),
          Result = expired;
    _ -> NewCache = Cache#{Name => NewEntries},
         Result = {hit, records(NewEntries)}
  end,
  {NewCache, Result}.


-spec records([cached_record()]) -> [dns:record()].
records(Entries) ->
  [Record || {_, Record} <- Entries].

-spec expired(cached_record()) -> boolean().
expired(Record) ->
  expired(Record, right_now()).

expired({Received , #dns_record{ttl = Duration}}, When) ->
  When > Received + Duration.

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

%% Returns a normalized domain name.
normalize_name(Name) ->
  % For now, just lowercase it. There might be more to it than that in the
  % future.
  string:lowercase(Name).

-spec make_entry(dns:record(), monotonic_time()) -> cached_record().
make_entry(Record, CreatedAt) ->
  {CreatedAt, Record}.

right_now() ->
  erlang:monotonic_time(second).
