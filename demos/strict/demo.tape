# Records demos/media/strict.mp4: a process racing hallpass's check wins
# against lite mode and loses against strict mode. See demos/README.md.
#
# Run `make -C demos strict`. Strict mode needs BPF-LSM, so the demo runs on
# $STRICT_HOST over ssh (default: fedora): a host with bpf in
# /sys/kernel/security/lsm, Linux 6.12 or later and passwordless sudo, of
# the same architecture as this one. The tape builds race/, copies it and
# hallpass to ~/tmp/hallpass-demo-strict there, and uses a HOME in that
# directory: nothing is written in the remote home.

Require go
Require ssh
Require scp

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `H=${STRICT_HOST:-fedora} && CGO_ENABLED=0 go build -o $DEMO_DIR/race ./demos/strict/race && ssh $H 'rm -rf ~/tmp/hallpass-demo-strict && mkdir -p ~/tmp/hallpass-demo-strict/home/project' && scp -q hallpass $DEMO_DIR/race $H:tmp/hallpass-demo-strict/ && ssh -t $H 'cd ~/tmp/hallpass-demo-strict && PATH=$PWD:$PATH HOME=$PWD/home PS1="$ " exec bash --norc -i'`
Enter
Sleep 3s
Type `cd ~/project && echo '# my bashrc' > ~/.bashrc && mkdir -p ~/.config/hallpass && echo 'escalate = sudo' > ~/.config/hallpass/config && clear`
Enter
Sleep 500ms
Type@1ms `clear && printf '\n\n   \033[1mLite mode can be raced, strict mode cannot\033[0m\n\n   race flips one byte of a path while it opens it:\n   ./.bashrc (in the project) or ../.bashrc (that is ~/.bashrc).\n' && sleep 6 && clear`
Enter
Sleep 300ms
Show
Sleep 5.5s
Hide
Sleep 800ms
Show

Type "# lite: hallpass checks the path, the kernel reads it again"
Enter
Type "hallpass --prompt=deny -- race"
Sleep 300ms
Enter
Wait+Screen@20s /escaped|no escape/
Wait+Line@10s /^\$/
Sleep 1.5s
Type "cat ~/.bashrc"
Enter
Sleep 3s
Type "# strict: the kernel checks the file it opens"
Enter
Type "hallpass --mode=strict --prompt=deny -- race"
Sleep 300ms
Enter
Wait+Screen@30s /no escape/
Wait+Line@10s /^\$/
Sleep 1.5s
Type "cat ~/.bashrc"
Enter
Sleep 5s

Hide
Type "exit"
Enter
Sleep 1s
