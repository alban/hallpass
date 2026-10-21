# Records demos/media/advance-grant.mp4: an agent asks in advance for the
# folder it will write during a long task; one card, one answer, then it
# works without prompting. See demos/README.md.
#
# Run `make -C demos advance-grant`. The Makefile runs it from the
# repository root, sets the output with `vhs -o` and gives a fresh directory
# as $DEMO_DIR. clean-home then makes HOME /home/me, on a tmpfs in a private
# mount namespace (needs passwordless sudo), so that the card shows a clean
# path: the demo writes nothing in yours.
#
# Exec mediation is off (--mediate=write): the demo is about writes, and
# the agent's programs would each be asked about.

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `cp -r demos/example $DEMO_DIR/project && cp demos/advance-grant/agent.sh $DEMO_DIR/project/agent && mkdir $DEMO_DIR/bin && cp hallpass $DEMO_DIR/bin/ && exec demos/advance-grant/clean-home $DEMO_DIR`
Enter
Sleep 1s
Type `clear`
Enter
Sleep 500ms
Type@1ms `clear && printf '\n\n   \033[1mAsk in advance\033[0m\n\n   Before a long task, the agent asks for the folder it will write:\n   one question while you are there, then no prompt while you are away.\n' && sleep 4 && clear`
Enter
Sleep 300ms
Show
Sleep 3.5s
Hide
Sleep 800ms
Show

Type "hallpass --mediate=write -- sh"
Sleep 300ms
Enter
Sleep 800ms
Type "./agent"
Sleep 300ms
Enter
Wait+Screen@10s /asks in advance/
Sleep 6s
# [g] grants the folder for the 30 minutes asked.
Type "g"
Wait+Screen@10s /parse.o/
Sleep 2.5s
Type "# the grant is a rule, with its expiry: Ctrl-]"
Enter
Sleep 1s
Ctrl+]
Sleep 5s
Type "q"
Sleep 500ms
Type "exit"
Enter
Sleep 1s
