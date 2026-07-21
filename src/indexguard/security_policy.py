"""Security policy constants shared by A enforcement and B analysis."""

HARD_BLOCK_ARTIFACT_TYPES = frozenset(
    {
        "ACTIVE_CONTENT",
        "ARCHIVE_LIMIT_EXCEEDED",
        "ENCRYPTED",
        "ENCRYPTED_DOCUMENT",
        "FORMAT_MISMATCH",
        "MACRO",
        "MALFORMED_ARCHIVE",
        "MALFORMED_DOCUMENT",
        "OLE",
        "PATH_TRAVERSAL",
        "SCRIPT",
        "SCRIPT_PAYLOAD",
        "UNSAFE_ARCHIVE",
        "UNSCANNABLE_ACTIVE_CONTENT",
        "UNSCANNABLE_CONTENT",
        "VBA",
        "ZIP_BOMB",
    }
)
