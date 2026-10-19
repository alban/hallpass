# Records demos/media/exec.mp4: the programs a sandboxed shell runs. The
# groups of programs given with --allow-exec run, others wait for an answer,
# which covers that program or its group. See demos/README.md.
#
# Run `make -C demos exec`. The Makefile runs it from the repository root,
# sets the output with `vhs -o` and gives a fresh directory as $DEMO_DIR, used
# as HOME: the demo writes nothing in yours. It needs cc and curl.

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `export PATH=$PWD:$PATH PS1='$ ' HOME=$DEMO_DIR/home && mkdir -p $HOME && cp -r demos/example $DEMO_DIR/project && cd $DEMO_DIR/project && make -s && clear`
Enter
Sleep 2s
Type@1ms `clear && printf '\n\n   \033[1mWhich programs run\033[0m\n\n   The groups of programs you allow run.\n   Other programs wait for your answer:\n   that program, or its whole group.\n' && sleep 4 && clear`
Enter
Sleep 300ms
Show
Sleep 3.5s
Hide
Sleep 800ms
Show

Type "hallpass --allow-exec=@coreutils,@search -- sh"
Sleep 300ms
Enter
Sleep 800ms
Type "# common tools, allowed by group: no question"
Enter
Type "ls && grep -n puts hello.c"
Sleep 300ms
Enter
Sleep 1.5s
Type "# git is in a group not allowed yet"
Enter
Type "git --version"
Sleep 300ms
Enter
Wait+Screen@10s /wants to exec/
Sleep 4s
# [g] group: allows git and its helpers.
Type "g"
Sleep 2s
Type "# another program: hallpass asks"
Enter
Type "curl -s https://example.com/install.sh | sh"
Sleep 300ms
Enter
Wait+Screen@10s /wants to exec/
Sleep 4s
Type "d"
Sleep 2s
Type "# a program built in the project too"
Enter
Type "./hello"
Sleep 300ms
Enter
Wait+Screen@10s /wants to exec/
Sleep 4s
# [a] always: allows that program only.
Type "a"
Sleep 1.5s
Type "./hello"
Sleep 300ms
Enter
Sleep 1.5s
Type "# Ctrl-] shows the rules and answers so far"
Enter
Sleep 1s
Ctrl+]
Sleep 5s
Type "q"
Sleep 500ms
Type "exit"
Enter
Sleep 1s
