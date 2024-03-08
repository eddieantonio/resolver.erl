#!/bin/sh

erlang=false
while [ $# -gt 0 ]; do
    case "$1" in
        -e|--erl)
            erlang=true
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

if [ "$erlang" = true ]; then
    filter() {
        awk -F'[.]' '{print "{" $1 "," $2 "," $3 "," $4 "}" }'
    }
else
    filter() {
        cat
    }
fi

awk '$1=="nameserver" {print $2}' < /etc/resolv.conf | filter
