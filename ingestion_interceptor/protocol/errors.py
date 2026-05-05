"""
Exception types raised by the wire protocol layer.

These are caught by the packet receiver and converted into security events
or dropped silently depending on severity. None of them should ever escape
the receiver thread.
"""


class PacketCodecError(Exception):
    """Base class for all packet-layer codec errors."""


class MalformedPacket(PacketCodecError):
    """
    The raw bytes do not form a valid packet: bad magic, truncated header,
    payload length lies, or oversized payload. Almost always a hostile or
    corrupted packet — drop silently and log at WARNING.
    """


class UnsupportedVersion(PacketCodecError):
    """
    The packet's version byte is not one this codec understands. Surfaces
    as a security event because version-skew can be a downgrade attack
    indicator.
    """


class HmacMismatch(PacketCodecError):
    """
    The HMAC tag attached to the packet does not match the expected
    HMAC-SHA256 over (header || payload) using the drone's shared key.
    Indicates wire tampering, MITM, or unknown drone — always drop.
    """


class SubmissionCodecError(Exception):
    """Base class for all binary-submission marshalling errors."""


class MalformedSubmission(SubmissionCodecError):
    """
    The reassembled byte stream cannot be decoded into a DroneSubmission:
    bad magic, unknown field tag, length lies, or truncated TLV record.
    """
