"""BusyBox-style --help text for the fake shell's applets.

Content is transcribed from BusyBox's own applet documentation
(https://www.busybox.net/downloads/BusyBox.html), matching this honeypot's
BusyBox/embedded-Linux persona (spec sec 4.2) rather than GNU coreutils man
pages -- a real device built on BusyBox prints this terse tabular style, not
a GNU-style man page, when a dropper script probes `<cmd> --help` before
deciding how to invoke something.

Deliberately excludes ash shell builtins that don't have their own --help
handling in real BusyBox (`cd`, `exit`, `logout`) -- see the comment at the
call site in honeypot/shell/commands.py for why `cd --help` is intentionally
left OUT of this dict.
"""
from __future__ import annotations

HELP_TEXT: dict[str, str] = {
    "ls": (
        "Usage: ls [-1AacCdeFilnpLRrSsTtuvwxXhk] [FILE]...\n\n"
        "List directory contents\n\n"
        "\t-1\tList in a single column\n"
        "\t-a\tDo not hide entries starting with .\n"
        "\t-A\tDo not list implied . and ..\n"
        "\t-C\tList by columns\n"
        "\t-d\tList directory entries instead of contents\n"
        "\t-F\tAppend indicator (one of */=@|) to entries\n"
        "\t-i\tList inode numbers\n"
        "\t-l\tUse a long listing format\n"
        "\t-L\tFollow symbolic links\n"
        "\t-n\tList numeric UIDs and GIDs instead of names\n"
        "\t-p\tAppend indicator to directories\n"
        "\t-R\tList subdirectories recursively\n"
        "\t-r\tSort in reverse order\n"
        "\t-S\tSort by file size\n"
        "\t-s\tPrint size of each file, in blocks\n"
        "\t-t\tSort by modification time\n"
        "\t-u\tSort by last access time\n"
        "\t-X\tSort by extension\n"
        "\t-h\tPrint sizes in human readable format (e.g., 1K 234M 2G)"
    ),
    "cp": (
        "Usage: cp [OPTIONS] SOURCE DEST\n\n"
        "Copy SOURCE to DEST, or multiple SOURCEs to DIRECTORY\n\n"
        "\t-a\tSame as -dpR\n"
        "\t-d,-P\tPreserve symlinks\n"
        "\t-H,-L\tFollow symlinks\n"
        "\t-p\tPreserve file attributes if possible\n"
        "\t-f\tOverwrite\n"
        "\t-i\tPrompt before overwrite\n"
        "\t-R,-r\tRecurse\n"
        "\t-l,-s\tCreate (sym)links"
    ),
    "mv": (
        "Usage: mv [OPTIONS] SOURCE DEST\n"
        "   or: mv [OPTIONS] SOURCE... DIRECTORY\n\n"
        "Rename SOURCE to DEST, or move SOURCE(s) to DIRECTORY\n\n"
        "\t-f\tDon't prompt before overwriting\n"
        "\t-i\tInteractive, prompt before overwrite"
    ),
    "rm": (
        "Usage: rm [OPTIONS] FILE...\n\n"
        "Remove (unlink) FILEs\n\n"
        "\t-i\tAlways prompt before removing\n"
        "\t-f\tNever prompt\n"
        "\t-R,-r\tRecurse"
    ),
    "cat": (
        "Usage: cat [-u] [FILE]...\n\n"
        "Concatenate FILEs and print them to stdout\n\n"
        "\t-u\tUse unbuffered I/O (ignored)"
    ),
    "echo": (
        "Usage: echo [-neE] [ARG]...\n\n"
        "Print the specified ARGs to stdout\n\n"
        "\t-n\tSuppress trailing newline\n"
        "\t-e\tInterpret backslash escapes (i.e., \\t=tab)\n"
        "\t-E\tDon't interpret backslash escapes (default)"
    ),
    "mkdir": (
        "Usage: mkdir [OPTIONS] DIRECTORY...\n\n"
        "Create DIRECTORY\n\n"
        "\t-m MODE\tMode\n"
        "\t-p\tNo error if exists; make parent directories as needed"
    ),
    "touch": (
        "Usage: touch [-c] [-d DATE] FILE...\n\n"
        "Update the last-modified date on FILEs\n\n"
        "\t-c\tDo not create files\n"
        "\t-d DT\tDate/time to use"
    ),
    "ps": (
        "Usage: ps\n\n"
        "Show list of processes\n\n"
        "\t-o COL1,COL2=HEADER\tSelect columns for display\n"
        "\t-T\tShow threads"
    ),
    "chmod": (
        "Usage: chmod [-Rcvf] MODE[,MODE]... FILE...\n\n"
        "Each MODE is one or more of the letters ugoa, one of the\n"
        "symbols +-= and one or more of the letters rwxXst\n\n"
        "\t-R\tRecurse\n"
        "\t-c\tList changed files\n"
        "\t-v\tList all files\n"
        "\t-f\tHide errors"
    ),
    "grep": (
        "Usage: grep [-HhrilLnqvsoweFEABCz] PATTERN [FILE]...\n\n"
        "Search for PATTERN in FILEs (or stdin)\n\n"
        "\t-H\tAdd 'filename:' prefix\n"
        "\t-h\tDo not add 'filename:' prefix\n"
        "\t-r\tRecurse\n"
        "\t-i\tIgnore case\n"
        "\t-l\tShow only names of files that match\n"
        "\t-L\tShow only names of files that don't match\n"
        "\t-n\tPrint line number with output lines\n"
        "\t-q\tDon't print anything, return 0 if PATTERN is found\n"
        "\t-v\tSelect non-matching lines\n"
        "\t-s\tSuppress open and read errors\n"
        "\t-o\tShow only the matching part of the line\n"
        "\t-c\tShow only count of matching lines\n"
        "\t-w\tMatch whole words only\n"
        "\t-e PTRN\tPattern to match\n"
        "\t-A N\tPrint N lines of trailing context\n"
        "\t-B N\tPrint N lines of leading context"
    ),
    "sed": (
        "Usage: sed [-inrzE] [-f FILE]... [-e CMD]... [FILE]...\n\n"
        "\t-e CMD\tAdd CMD to sed commands to be executed\n"
        "\t-f FILE\tAdd FILE contents to sed commands to be executed\n"
        "\t-i\tEdit files in-place (else write to stdout)\n"
        "\t-n\tSuppress automatic printing of pattern space\n"
        "\t-r,-E\tUse extended regex syntax\n\n"
        "If no -e or -f, the first non-option argument is the sed command"
    ),
    "awk": (
        "Usage: awk [OPTIONS] [AWK_PROGRAM] [FILE]...\n\n"
        "\t-v VAR=VAL\tSet variable\n"
        "\t-F SEP\tUse SEP as field separator\n"
        "\t-f FILE\tRead program from FILE"
    ),
    "ifconfig": (
        "Usage: ifconfig [-a] interface [address]\n\n"
        "Configure a network interface\n\n"
        "\t[[-]broadcast [ADDRESS]] [[-]pointopoint [ADDRESS]]\n"
        "\t[netmask ADDRESS] [dstaddr ADDRESS]\n"
        "\t[outfill NN] [keepalive NN]\n"
        "\t[hw ether|infiniband ADDRESS] [metric NN] [mtu NN]\n"
        "\t[[-]trailers] [[-]arp] [[-]allmulti]\n"
        "\t[multicast] [[-]promisc] [txqueuelen NN] [[-]dynamic]\n"
        "\t[mem_start NN] [io_addr NN] [irq NN]\n"
        "\t[up|down] ..."
    ),
    "ping": (
        "Usage: ping [OPTIONS] HOST\n\n"
        "Send ICMP ECHO_REQUEST packets to network hosts\n\n"
        "\t-4,-6\tForce IP or IPv6 name resolution\n"
        "\t-c CNT\tSend only CNT pings\n"
        "\t-s SIZE\tSend SIZE data bytes in packets (default 56)\n"
        "\t-I IFACE/IP\tUse interface or IP address as source\n"
        "\t-W SEC\tSeconds to wait for the first response\n"
        "\t-w SEC\tSeconds until ping exits\n"
        "\t-q\tQuiet, only displays output at start and when finished"
    ),
    "top": (
        "Usage: top [-b] [-nCOUNT] [-dSECONDS] [-m]\n\n"
        "Provide a view of process activity in real time.\n"
        "Read the status of all processes from /proc each SECONDS\n"
        "and display a screenful of them.\n\n"
        "\t-b\tRun in batch mode\n"
        "\t-n COUNT\tExit after COUNT iterations\n"
        "\t-d SECONDS\tDelay between updates\n"
        "\t-m\tSame as top -m"
    ),
    "vi": (
        "Usage: vi [OPTIONS] [FILE]...\n\n"
        "Edit FILE\n\n"
        "\t-c CMD\tInitial command to run ($EXINIT and .exrc are disabled)\n"
        "\t-H\tLong help message\n"
        "\t-R\tRead-only - do not write to the files\n"
        "\t-s\tScript mode (skip initialization)"
    ),
    "mount": (
        "Usage: mount [flags] DEVICE NODE [-o OPT,OPT]\n\n"
        "Mount a filesystem. Filesystem autodetection requires /proc.\n\n"
        "\t-a\tMount all filesystems in fstab\n"
        "\t-f\tDry run\n"
        "\t-i\tDon't run mount helper\n"
        "\t-r\tRead-only mount\n"
        "\t-w\tRead-write mount (default)\n"
        "\t-t FSTYPE\tFilesystem type\n"
        "\t-O OPT\tMount only filesystems with option OPT (with -a)"
    ),
    "ip": (
        "Usage: ip [OPTIONS] {address | route | link | tunnel | rule} {COMMAND}\n\n"
        "\t-f[amily] {inet|inet6|link}\tSelect address family\n"
        "\t-o[neline]\tOutput each record on a single line"
    ),
    "uname": (
        "Usage: uname [-amnrsvp]\n\n"
        "Print system information\n\n"
        "\t-a\tPrint all\n"
        "\t-m\tThe machine (hardware) type\n"
        "\t-n\tHostname\n"
        "\t-r\tKernel release\n"
        "\t-s\tKernel name (default)\n"
        "\t-v\tKernel version\n"
        "\t-p\tProcessor type"
    ),
    "whoami": (
        "Usage: whoami\n\n"
        "Print the user name associated with the current effective user ID"
    ),
    "id": (
        "Usage: id [OPTIONS] [USER]\n\n"
        "Print information about USER or the current user\n\n"
        "\t-u\tPrint user ID\n"
        "\t-g\tPrint group ID\n"
        "\t-G\tPrint supplementary group IDs\n"
        "\t-n\tPrint name instead of number\n"
        "\t-r\tPrint real ID instead of effective ID"
    ),
    "df": (
        "Usage: df [-Pkmhai] [-B SIZE] [FILESYSTEM]...\n\n"
        "Print filesystem usage statistics\n\n"
        "\t-P\tPOSIX output format\n"
        "\t-k\t1024-byte blocks (default)\n"
        "\t-m\t1M-byte blocks\n"
        "\t-h\tHuman readable (e.g. 1K 243M 2G)\n"
        "\t-a\tShow all filesystems\n"
        "\t-i\tInode information\n"
        "\t-B SIZE\tBlocksize"
    ),
    "free": (
        "Usage: free\n\n"
        "Display the amount of free and used system memory"
    ),
    "pwd": (
        "Usage: pwd\n\n"
        "Print the full filename of the current working directory"
    ),
    "wget": (
        "Usage: wget [-c|--continue] [--spider] [-q|--quiet]\n"
        "\t[-O|--output-document FILE] [--header 'header: value']\n"
        "\t[-Y|--proxy on/off] [-P DIR] [-U|--user-agent AGENT]\n"
        "\t[-T SEC] URL...\n\n"
        "Retrieve files via HTTP or FTP\n\n"
        "\t-s\tSpider mode - only check file existence\n"
        "\t-c\tContinue retrieval of aborted transfer\n"
        "\t-q\tQuiet\n"
        "\t-P DIR\tSave to DIR (default cwd)\n"
        "\t-O FILE\tSave to FILE ('-' for stdout)\n"
        "\t-T SEC\tNetwork read timeout is SEC seconds\n"
        "\t-U STR\tUse STR for User-Agent header\n"
        "\t--no-check-certificate\tDon't validate the server's certificate"
    ),
}
