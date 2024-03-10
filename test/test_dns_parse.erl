-module(test_dns_parse).

-include_lib("eunit/include/eunit.hrl").

basic_test() ->
  Binary = <<65,56,129,128,0,1,0,1,0,2,0,0, % Header
             7,"example",3,"com",0,0,1,0,1, % Question
             192,12,0,1,0,1,0,0,48,7,0,4,93,184,216,34, % Answer
             192,12,0,2,0,1,0,0,48,7,0,20,1,"a",12,"iana-servers",3,"net",0, % Authority 1
             192,12,0,2,0,1,0,0,48,7,0,4,1,"b",192,59 % Authority 2
           >>,
  Expected = #{id => 16696,
    flags => [response,standard_query,recursion_desired,
              recursion_available],
    questions => [{dns_question,"example.com",a,in}],
    answers => [{dns_record,"example.com",a,in,12295,{93,184,216,34}}],
    authorities => [{dns_record,"example.com",ns,in,12295,"a.iana-servers.net"},
                    {dns_record,"example.com",ns,in,12295,"b.iana-servers.net"}],
    additionals => []},
  Expected = dns_parse:packet(Binary).

non_resursive_test() ->
  Binary = <<146,129,128,128,0,1,0,1,0,2,0,0, % Header
             7,"example",3,"com",0,0,1,0,1, % Question 1
             192,12,0,1,0,1,0,0,47,114,0,4,93,184,216,34, % Answer 1
             192,12,0,2,0,1,0,0,47,114,0,20,1,"b",12,"iana-servers",3,"net",0, % Authority 1
             192,12,0,2,0,1,0,0,47,114,0,4,1,"a",192,59 % Authority 2
           >>,
  Expected = #{id => 37505,
               flags => [response,standard_query,recursion_available],
               questions => [{dns_question,"example.com",a,in}],
               answers => [{dns_record,"example.com",a,in,12146,{93,184,216,34}}],
               authorities => [{dns_record,"example.com",ns,in,12146,"b.iana-servers.net"},
                               {dns_record,"example.com",ns,in,12146,"a.iana-servers.net"}],
               additionals => []},
  Expected = dns_parse:packet(Binary).


malicious_compression_test() ->
  Binary = <<146,129,128,128,0,1,0,0,0,0,0,0, % Header
             % <<192, 12>> is a pointer back to the 12th byte,
             % which is right here, causing an infinite loop.
             192,12,0,1,0,1
           >>,
  {error, _} = dns_parse:packet(Binary).
