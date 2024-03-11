%%% @doc Information about upstream resolvers.
-module(dns_upstream).

-export([from_etc/0]).


% Public API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec from_etc() -> [inet:ip4_address()].
%% @doc Returns the IP addresses of any resolvers found in /etc/resolv.conf
%%
%% Type <code>man 5 resolver</code> in your terminal for more information.
from_etc() ->
    {ok, File} = file:open("/etc/resolv.conf", [read, {encoding, utf8}]),
    Lines = lines(File),
    ok = file:close(File),
    parse_resolve_conf(Lines).


% Internal %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

parse_resolve_conf(Lines) ->
    [parse_nameserver(Line) || Line <- Lines, starts_with_nameserver(Line)].

parse_nameserver(Line) ->
    ["nameserver", Rest] = string:split(Line, " "),
    IPString = string:trim(Rest, trailing),
    Components = string:split(IPString, ".", all),
    [A, B, C, D] = [list_to_integer(X) || X <- Components],
    {A, B, C, D}.

starts_with_nameserver(Line) ->
    string:prefix(Line, "nameserver") =/= nomatch.

lines(File) ->
    lines(File, file:read_line(File), []).

lines(_, eof, Lines) ->
    lists:reverse(Lines);
lines(File, {ok, Line}, Acc) ->
    lines(File, file:read_line(File), [Line|Acc]).
