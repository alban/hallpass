# Records demos/hallpass.gif. See demos/README.md.
#
# Run `make -C demos hallpass.gif`, or from the repository root, after
# `go build -o hallpass ./cmd/hallpass`:
#   vhs demos/hallpass.tape

Output demos/hallpass.gif

Require copilot

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "export PATH=$PWD:$PATH PS1='$ ' && rm -rf /tmp/hallpass-demo && cp -r demos/example /tmp/hallpass-demo && cd /tmp/hallpass-demo && clear"
Enter
Sleep 500ms
Type@1ms `clear && printf '\n\n   \033[1m1/2  A shell under hallpass\033[0m\n\n   Writes inside the project go through.\n   Writes anywhere else wait for your answer.\n' && sleep 5 && clear`
Enter
Sleep 300ms
Show
Sleep 4.5s
Hide
Sleep 800ms
Show

# 1. A shell in the sandbox: the project is writable, the rest is asked.
Type "hallpass -- sh"
Sleep 300ms
Enter
Sleep 800ms
Type "# inside the project: no question"
Enter
Type "echo hello > notes.txt && cat notes.txt"
Sleep 300ms
Enter
Sleep 1.5s
Type "# outside: hallpass asks"
Enter
Type "echo '# pwned' >> ~/.bashrc"
Sleep 300ms
Enter
Wait+Screen@10s /wants to write/
Sleep 5s
Type "d"
Sleep 1.5s
Type "# Ctrl-] shows the rules and answers so far"
Enter
Sleep 1s
Ctrl+]
Sleep 6s
Type "q"
Sleep 500ms
Type "exit"
Enter
Sleep 1s

Hide
Type@1ms `rm -f notes.txt && clear && printf '\n\n   \033[1m2/2  An agent with every permission: copilot --yolo\033[0m\n\n   Asked to build and install a project. The install step copies a file\n   into ~/.local/bin, outside the project, so hallpass asks.\n' && sleep 6 && clear`
Enter
Sleep 300ms
Show
Sleep 5.5s
Hide
Sleep 800ms
Show

# 2. An agent with every permission, building and installing a project; the
# install writes outside the project, so hallpass asks.
Type "hallpass -allow ~/.copilot -allow ~/.cache/copilot -- copilot --model claude-haiku-4.5 --yolo"
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
