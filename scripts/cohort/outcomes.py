"""Parsers for the two outcomes a commit message states outright.

SZZ infers that a change was defective; these two record someone saying so.
They cost nothing to collect — the evidence is already in the history — and
they are the high-precision end of the outcome ladder, which is what makes them
worth having even though their recall is poor:

    revert      "This reverts commit <sha>" is written by ``git revert`` itself
                and names the reverted commit exactly.  Very high precision,
                low recall (a revert is a strong reaction), and unlike SZZ it
                needs no blame at all.
    Fixes:      a trailer naming the commit that introduced the bug.  Exact
                where it appears, but its use is a project habit rather than a
                convention, so recall varies enormously between repositories.
                That variation is itself a confounder — a repository that
                writes `Fixes:` diligently will look buggier — so this stays a
                tertiary outcome and is reported per repository.

Both parsers are deliberately SHA-precise.  Matching subjects instead
("Revert \"fix the parser\"") would pick up unrelated commits that happen to
share wording.
"""

from __future__ import annotations

import re

# `git revert` writes this line verbatim; a full 40-hex sha, optionally
# followed by a period.  Requiring the full sha keeps the match exact.
REVERT_RE = re.compile(
    r"^[ \t]*This reverts commit[ \t]+(?P<sha>[0-9a-f]{40})\b",
    re.IGNORECASE | re.MULTILINE,
)

# `Fixes: <abbrev> ("subject")`.  The colon is load-bearing: GitHub's
# "Fixes #123" closes an *issue* and says nothing about a commit, and dropping
# the colon would silently turn issue numbers into commit references.
FIXES_TRAILER_RE = re.compile(
    r"^[ \t]*Fixes:[ \t]+(?P<sha>[0-9a-f]{7,40})\b",
    re.IGNORECASE | re.MULTILINE,
)


def reverted_shas(message: str) -> list[str]:
    """Return the full SHAs a message says it reverts, lowercased and unique."""

    if not isinstance(message, str):
        return []
    seen: dict[str, None] = {}
    for match in REVERT_RE.finditer(message):
        seen.setdefault(match.group("sha").lower(), None)
    return list(seen)


def fixes_trailer_shas(message: str) -> list[str]:
    """Return the (possibly abbreviated) SHAs a ``Fixes:`` trailer names.

    Abbreviations are returned as written; resolving them to full SHAs needs the
    repository and is the caller's job.
    """

    if not isinstance(message, str):
        return []
    seen: dict[str, None] = {}
    for match in FIXES_TRAILER_RE.finditer(message):
        seen.setdefault(match.group("sha").lower(), None)
    return list(seen)
