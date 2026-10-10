import argparse
import json
import sys

from backend.satra import ingest
from backend.satra.settings import load_settings


def show_change_set(change_set):
    print("sha:     " + change_set["sha"])
    print("base:    %s (%s)" % (change_set["base"], change_set["base_kind"]))
    print("parents: " + ", ".join(change_set["parents"]))
    print("merge:   " + str(change_set["merge"]))
    print("author:  %s  %s" % (change_set["author"], change_set["date"]))
    print("message: " + change_set["message"].splitlines()[0] if change_set["message"] else "message: ")
    print("files:")
    for row in change_set["files"]:
        origin = " (from %s)" % row["old_path"] if row["old_path"] else ""
        flag = " [binary]" if row["binary"] else ""
        print("  %-9s %s%s%s  +%d -%d" % (row["status"], row["path"], origin, flag, row["additions"], row["deletions"]))
    print("diff:")
    for row in change_set["files"]:
        print(row["diff"] if row["diff"] else "(no text diff for %s)" % row["path"])


def command_ingest(arguments):
    settings = load_settings()
    repo_dir = ingest.ensure_repository(settings)
    if arguments.list:
        for row in ingest.list_recent_commits(repo_dir, arguments.limit):
            print("%s  %-40s %s" % (row["sha"], ",".join(row["refs"]), row["message"]))
        return 0
    if arguments.sha is None:
        print("error: --sha is required unless --list is given", file=sys.stderr)
        return 2
    change_set = ingest.ingest_commit(repo_dir, arguments.sha)
    if arguments.json:
        print(json.dumps(change_set, indent=2))
    else:
        show_change_set(change_set)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="satra")
    sub = parser.add_subparsers(dest="command", required=True)
    pick = sub.add_parser("ingest")
    pick.add_argument("--sha")
    pick.add_argument("--list", action="store_true")
    pick.add_argument("--limit", type=int, default=20)
    pick.add_argument("--json", action="store_true")
    pick.set_defaults(handler=command_ingest)
    return parser


def main(argv=None):
    arguments = build_parser().parse_args(argv)
    try:
        return arguments.handler(arguments)
    except ingest.IngestError as problem:
        print("rejected: %s" % problem, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
