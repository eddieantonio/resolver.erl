%%%-------------------------------------------------------------------
%% @doc dns top level supervisor.
%% Starts the DNS server on the configured port.
%% @end
%%%-------------------------------------------------------------------

-module(dns_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    % Figure out the port.
    Port = case application:get_env(port) of
               {ok, P} -> P;
               undefined -> 9001
           end,
    supervisor:start_link({local, ?SERVER}, ?MODULE, [Port]).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
init([Port]) ->
    SupFlags = #{strategy => one_for_all,
                 intensity => 1,
                 period => 1},
    ChildSpecs = [#{id => dns_server,
                    start => {dns_server, start_link, [Port]},
                    restart => permanent}],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
