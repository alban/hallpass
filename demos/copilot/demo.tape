# Records demos/media/copilot.mp4: copilot --yolo under hallpass. See
# demos/README.md.
#
# Run `make -C demos copilot`. The Makefile runs it from the repository root
# and sets the output with `vhs -o`. The project is copied to
# /tmp/hallpass-demo (or $HALLPASS_DEMO_PROJECT), a fixed path: trust it in
# copilot once beforehand.
#
# Exec mediation is off (--mediate=write): copilot runs many programs, and
# the demo is about a write outside the project.

Require copilot

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `export PATH=$PWD:$PATH PS1='$ ' D=${HALLPASS_DEMO_PROJECT:-/tmp/hallpass-demo} && rm -rf "$D" && cp -r demos/example "$D" && cd "$D" && clear`
Enter
Sleep 500ms
Type@1ms `clear && printf '\n\n   \033[1mAn agent with every permission: copilot --yolo\033[0m\n\n   Asked to build and install a project. The install step copies a file\n   into ~/.local/bin, outside the project, so hallpass asks.\n' && sleep 6 && clear`
Enter
Sleep 300ms
Show
Sleep 5.5s
Hide
Sleep 800ms
Show

Type "hallpass --mediate=write --allow-path ~/.copilot --allow-path ~/.cache/copilot -- copilot --model claude-haiku-4.5 --yolo"
Sleep 3s
Enter
Wait+Screen@60s /Check for mistakes/
Sleep 2s
Type "Build and install the project"
Sleep 500ms
Enter
Sleep 3s
Hide
Wait+Screen@120s /wants to write/
Show
Sleep 7s
Type "d"
Sleep 1s
Hide
Wait+Screen@120s /Allow All/
Show
Sleep 6s
Ctrl+C
Sleep 300ms
Ctrl+C
Wait+Screen@20s /Resume/
Sleep 2s

Hide
Type@1ms `clear && printf '\n\n   \033[1mhallpass\033[0m: run your agent, answer for what it writes outside the project.\n\n   github.com/alban/hallpass\n' && sleep 6`
Enter
Sleep 300ms
Show
Sleep 5s
