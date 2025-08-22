# Persistence Helpers

The `bounty_hunter.persistence` module provides optional utilities for
safely checking whether the application can write to disk and for
storing minimal data used to verify persistence between runs.

## Writable checks

Use `is_writable` or `check_writable` to determine if a file or
 directory is writable without modifying it:

```python
from bounty_hunter.persistence import is_writable

if is_writable("config.yaml"):
    print("config can be updated")
```

The check is non-destructive and falls back to the parent directory when
the file does not yet exist.

## Nonce files

Modules that need to confirm persistence can write a nonce file and
later verify its value:

```python
from bounty_hunter.persistence import write_nonce, verify_nonce

path, value = write_nonce("/tmp/bh")
# ... later ...
assert verify_nonce(path, value)
```

Nonce files contain only a random token and can be removed once they are
no longer needed.

## Safe usage

These helpers are optional; they will never modify existing files unless
you explicitly call `write_nonce`.  The small nonce files are created
in user-specified directories and are safe to delete.
