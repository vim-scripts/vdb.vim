#!/bin/sh

RUBY=${RUBY-ruby}
TTYNAME="$2"
PROGNAME="$3"

echo "$@" > /dev/pts/2

if [ $# -le 2 ]; then
	echo "Usage: $0 -t TTY PROGRAM [ARGS...]"
	exit 1
fi

shift 3
echo "$@" > /dev/pts/2

"$RUBY" -rvdbruby "$PROGNAME" -t "$TTYNAME" "$@"
echo "Program exited." 2> /dev/null

# necessary for vdb.vim normal quit
echo -n "(rdb) " 2> /dev/null
