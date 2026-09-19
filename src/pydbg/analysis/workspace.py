"""Workspace — names and comments for one image, saved and reloaded.

The reason this exists is that analysis is expensive and naming is incremental:
a full pass over kernel32 takes half a minute, and what comes out of it is
several thousand addresses that a person then spends hours distinguishing.
Losing that work when the process exits makes the hours pointless, and keeping
it only in memory makes it impossible to share.

So a workspace is a small JSON file beside the image holding names and
comments, keyed by RVA — which is what makes it survive a re-run of the
analysis, and what makes it wrong to apply to a different binary. Hence the
image check below: refusing is the whole value, because names attached to the
wrong offsets read exactly like correct ones.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field

from .names import Name, NameTable, SOURCE_USER

FORMAT_VERSION = 1


class WorkspaceError(Exception):
    """A workspace could not be applied to the image it was given."""


def image_fingerprint(path, chunk=1 << 20):
    """A cheap identity for an image: size plus a hash of its ends.

    Hashing a 2MB binary is fine; hashing a 200MB one on every load is not, and
    the ends plus the size are enough to catch the case that matters — a
    workspace applied to a binary that is not the one it was built from.
    """
    size = os.path.getsize(path)
    digest = hashlib.sha256()
    digest.update(str(size).encode("ascii"))
    with open(path, "rb") as handle:
        digest.update(handle.read(chunk))
        if size > chunk:
            handle.seek(max(size - chunk, chunk))
            digest.update(handle.read(chunk))
    return {"size": size, "sha256": digest.hexdigest()}


@dataclass
class Workspace:
    """Names, comments and the image they belong to."""

    image: dict = field(default_factory=dict)      # fingerprint
    names: NameTable = field(default_factory=NameTable)
    comments: dict = field(default_factory=dict)   # rva -> text
    path: str = None

    # ── content ────────────────────────────────────────────────

    def name(self, rva, text, source=SOURCE_USER):
        """Attach a name. Returns True if it displaced an existing one."""
        return self.names.add(rva, text, source)

    def comment(self, rva, text):
        """Attach a comment to an address. An empty text removes it."""
        if text:
            self.comments[rva] = text
        else:
            self.comments.pop(rva, None)

    def comment_of(self, rva):
        return self.comments.get(rva)

    def label(self, rva):
        return self.names.label(rva)

    def __len__(self):
        return len(self.names) + len(self.comments)

    # ── files ──────────────────────────────────────────────────

    def to_dict(self):
        return {
            "version": FORMAT_VERSION,
            "image": self.image,
            "names": self.names.to_dict(),
            "comments": {f"{rva:#x}": text
                         for rva, text in sorted(self.comments.items())},
        }

    def save(self, path=None):
        """Write the workspace. Sorted, so two saves of the same work match."""
        target = path or self.path
        if not target:
            raise WorkspaceError("no path given and none recorded")
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=1, sort_keys=True)
            handle.write("\n")
        self.path = target
        return target

    @classmethod
    def from_dict(cls, raw):
        version = raw.get("version")
        if version != FORMAT_VERSION:
            raise WorkspaceError(
                f"workspace format {version!r}, this build writes "
                f"{FORMAT_VERSION}")
        workspace = cls(image=raw.get("image", {}))
        workspace.names = NameTable.from_dict(raw.get("names"))
        for key, text in (raw.get("comments") or {}).items():
            workspace.comments[int(key, 0)] = text
        return workspace

    @classmethod
    def load(cls, path, image_path=None, strict=True):
        """Read a workspace, checking it belongs to 'image_path'.

        'strict' refuses a mismatch rather than applying names to offsets they
        were not written for. Passing strict=False is for the case where the
        binary was rebuilt and the addresses are known to still hold, which is
        a judgement the caller has to make explicitly.
        """
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        workspace = cls.from_dict(raw)
        workspace.path = path
        if image_path:
            workspace.check_image(image_path, strict=strict)
        return workspace

    def check_image(self, image_path, strict=True):
        """Confirm the workspace was built for 'image_path'."""
        actual = image_fingerprint(image_path)
        recorded = self.image or {}
        if not recorded:
            if strict:
                raise WorkspaceError(
                    f"{self.path or 'workspace'} records no image, so it cannot "
                    f"be checked against {image_path}")
            return False
        if recorded == actual:
            return True
        message = (f"{self.path or 'workspace'} was built for a different "
                   f"image: recorded size {recorded.get('size')} / hash "
                   f"{str(recorded.get('sha256'))[:12]}, given {actual['size']} "
                   f"/ {actual['sha256'][:12]}")
        if strict:
            raise WorkspaceError(message)
        return False

    @classmethod
    def for_image(cls, image_path):
        """An empty workspace bound to an image."""
        return cls(image=image_fingerprint(image_path), path=None)


def apply_to_names(table, workspace):
    """Merge a workspace's names into a table, person-supplied names winning."""
    for rva, name in workspace.names.items():
        if isinstance(name, Name):
            table.add(rva, name.text, name.source)
        else:
            table.add(rva, name, SOURCE_USER)
    return table
