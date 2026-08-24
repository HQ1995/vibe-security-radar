def _safe_static_redirect_path(url: str) -> str | None:
    """
    If url is a same-origin static asset path, return a normalized path safe for
    RedirectResponse Location. Otherwise None (caller should fall back to default).
    Rejects traversal (..), encoded dots, query/fragment, and non-/static targets.
    """
    if not url or not isinstance(url, str):
        return None
    path = url.split('?', 1)[0].split('#', 1)[0].strip()
    for _ in range(2):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if '\x00' in path or '\\' in path:
        return None
    if not path.startswith('/'):
        return None
    normalized = posixpath.normpath(path)
    if normalized in ('.', '/'):
        return None
    if not (normalized == '/static' or normalized.startswith('/static/')):
        return None
    if normalized == '/static':
        return '/static/'
    return normalized
