# Session log

One file per entry, named `<YYYY-MM-DD>T<HHMM>-<row>.md`. Append by adding a
file. Never edit one that is not yours and never edit one that is committed.

```text
planning/typescript-sdk-port/log/2026-07-25T1544-w05.md
```

## Why this is a directory

It was a section of `review-checklist.md` until `2026-07-25`. The two things in
that file have opposite write patterns: the queue table is mutable and edited
constantly, and the log is append-only and written once at the end of a session.
Sharing a file made an append inherit the table's write races.

That is not a theory. Five wallet rows were upgraded to `done` by a re-review
whose entries never landed: `23a3ce76` committed the table cells by pathspec
while the entries were still unwritten, and the worker's session ended. The
[parity evidence audit](../row-updates/parity-evidence-audit.md) found the rows
claiming parity with nothing behind them, and the entries had to be
reconstructed from the cells they had been separated from, with the reviewer's
identity permanently lost. A new file cannot be carried off that way, because it
does not appear in another worker's diff.

The alternative considered and rejected was one file per row for all 145 rows,
which costs about a day and would have prevented five of the thirty-five
failures the audit found. Most of the rest were workers relaying evidence they
had not run, which no file layout prevents. See the
[2026-07-25 log-split entry](2026-07-25T2010-log-split.md).

## The history this replaces

`git log -p -- planning/typescript-sdk-port/review-checklist.md` is what made
the parity evidence audit possible: six commits accounted for all 36 unsupported
`done` upgrades, and three accounted for 32. That history is intact and still
answers questions about anything before the split. The pre-migration revision,
the last commit where the log and the table shared a file, is:

```text
b54f3d57
```

For anything after it, the equivalent query is better rather than worse, because
each entry is now an atomic file addition:

```bash
# every entry, newest first, with the commit that added it
git log --diff-filter=A --format='%h %ad %s' --date=short --name-only -- planning/typescript-sdk-port/log/

# what else rode along in the commit that added one entry
git log -1 --stat -- planning/typescript-sdk-port/log/2026-07-25T1544-w05.md
```

What is genuinely lost is a single chronological `git log -p` covering both
sides of the split. Nothing reconstructs that except reading the two ranges in
sequence.

## Ordering

Entries are ordered by the timestamp in the filename, not by directory listing,
not by file mtime, and not by commit date. Two entries in the same minute keep a
stable order by filename.

Document order used to carry that meaning and carried it badly: workers wrote
per-row entries in row order rather than in time order, so the old log had
`2026-07-25 00:45` sitting above `2026-07-24 23:49`. Moving to timestamps
changed the last recorded verdict for no row; the migration checked every one
and reported the difference before writing.

## What the check reads

`sdk-libs/ts/config/review-checklist-check.mjs`, run by the `typescript /
planning` CI job, reads every file here and refuses a row that is `done` /
`PARITY` in the table while the most recent entry assigning it a verdict records
an adverse one.

**Adding a file proves nothing.** 31 of the 36 rows in the audit had an entry,
so a presence test would have passed almost all of them. The check reads the
verdict, and only from a `Verdict:` field or a field named for a verdict, and
only when the line carries exactly one verdict. A line naming several rows and
several verdicts attributes nothing rather than the wrong thing. `Exact next
file` is ignored outright: every entry names its successor there, so a plain
scan would attribute each verdict to the next row in the queue.

Run it with `--explain` to see what was attributed to each row.
