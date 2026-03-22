"""Fetch source files from django/django on GitHub."""

import requests


def fetch_file(filename: str, sha: str, repo: str = "django/django") -> str:
    """Fetch a file from a GitHub repo at a specific commit SHA.

    Returns the file contents as a string, or empty string on failure.
    """
    url = f"https://raw.githubusercontent.com/{repo}/{sha}/{filename}"
    resp = requests.get(url, timeout=30)
    if resp.status_code != 200:
        return ""
    return resp.text


def extract_context(
    source: str,
    pattern: str,
    before: int = 5,
    after: int = 80,
) -> str:
    """Extract a window of code around the first occurrence of pattern.

    Searches for the pattern in each line. Returns `before` lines before
    the first match through `after` lines after the last match.
    If no match, returns the first `after` lines.
    """
    lines = source.split("\n")
    search_terms = [t.strip() for t in pattern.split(" and ")]

    first = None
    last = None
    for i, line in enumerate(lines):
        for term in search_terms:
            if term in line:
                if first is None:
                    first = i
                last = i

    if first is None:
        return "\n".join(lines[:after])

    start = max(0, first - before)
    end = min(len(lines), (last or first) + after)
    return "\n".join(lines[start:end])
