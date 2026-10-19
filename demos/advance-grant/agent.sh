#!/bin/sh
# A pretend agent for demos/advance-grant: before a long unattended task,
# it asks for the folder it will write, then works without prompting.

cache=$HOME/.cache/build
# hallpass answers with an errno: the shell prints its message.
ask() {
	msg=$(sh -c "exec '/proc/self/hallpass/$1'" 2>&1 | sed 's/.*: //')
	case $msg in
	"File exists") echo "$msg (EEXIST: already allowed)" ;;
	"Operation already in progress") echo "$msg (EALREADY: granted)" ;;
	"No message of desired type") echo "$msg (ENOMSG: hallpass would ask)" ;;
	"Operation not permitted") echo "$msg (EPERM: denied)" ;;
	*) echo "$msg" ;;
	esac
}

q="op=write&path=$cache/**&for=30m"
echo "agent: may I write ~/.cache/build? $(ask "check?$q")"
echo "agent: asking for it now, for the next 30 minutes..."
echo "agent: $(ask "request?$q&reason=cache+object+files+during+the+nightly+build")"
mkdir "$cache"
for f in main util parse; do
	sleep 0.6
	echo "built $f" > "$cache/$f.o" && echo "agent: wrote ~/.cache/build/$f.o"
done
