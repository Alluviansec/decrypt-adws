#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Decrypt ADWS (Active Directory Web Services) NMS traffic from a pcap.

Parses IPv4/IPv6 TCP streams (default port 9389), extracts Kerberos
AP-REQ/AP-REP or NTLM challenge/authenticate to derive session keys,
then decrypts GSS-Wrap CFX tokens (Kerberos) or NTLM-sealed frames
containing .NET Binary XML (MC-NBFX / MC-NBFS) SOAP messages.

Supports pcap and pcapng formats, MIT keytab v2 files, NTLM authentication
via NT hash or password, and proper TCP reassembly with retransmission
deduplication and gap detection.

Usage:
    python decrypt_adws.py <pcap_file> [keytab_file] [--nthash HASH] [--password PW]

Requires: dpkt, minikerberos, pycryptodome (Cryptodome)
"""

import struct
import sys
import os
import uuid
import base64
import re
import argparse
import hashlib
import hmac
from collections import defaultdict, Counter

import dpkt
from minikerberos.protocol.asn1_structs import (
    AP_REQ, AP_REP, EncTicketPart, EncAPRepPart, Authenticator,
)
from minikerberos.protocol.encryption import Key, _enctype_table
from Cryptodome.Cipher import ARC4

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# ─── Keytab Parser ───────────────────────────────────────────────────────────

def parse_keytab(path):
    """Parse MIT keytab v2 file. Returns list of (principal, realm, kvno, enctype, Key)."""
    with open(path, 'rb') as f:
        data = f.read()

    if len(data) < 2 or data[:2] != b'\x05\x02':
        raise ValueError(f"Not a valid MIT keytab v2 file (magic: {data[:2].hex()})")

    entries = []
    pos = 2
    while pos < len(data):
        if pos + 4 > len(data):
            break
        entry_len = struct.unpack('>i', data[pos:pos + 4])[0]
        pos += 4
        if entry_len <= 0:
            # Negative = deleted entry (hole), skip abs(entry_len) bytes
            pos += abs(entry_len)
            continue
        entry_end = pos + entry_len
        if entry_end > len(data):
            break

        # Realm
        realm_len = struct.unpack('>H', data[pos:pos + 2])[0]; pos += 2
        realm = data[pos:pos + realm_len].decode('utf-8'); pos += realm_len

        # Principal components
        num_components = struct.unpack('>H', data[pos:pos + 2])[0]; pos += 2
        components = []
        for _ in range(num_components):
            clen = struct.unpack('>H', data[pos:pos + 2])[0]; pos += 2
            components.append(data[pos:pos + clen].decode('utf-8')); pos += clen

        principal = '/'.join(components)

        # Timestamp (4 bytes), VNO8 placeholder (4 bytes)
        pos += 4  # timestamp
        pos += 4  # name_type / zeros

        # kvno (1 byte), enctype (2 bytes), key
        kvno = data[pos]; pos += 1
        enctype = struct.unpack('>H', data[pos:pos + 2])[0]; pos += 2
        key_len = struct.unpack('>H', data[pos:pos + 2])[0]; pos += 2
        key_data = data[pos:pos + key_len]; pos += key_len

        # Optional 4-byte kvno extension (if entry has trailing bytes)
        if pos + 4 <= entry_end:
            kvno = struct.unpack('>I', data[pos:pos + 4])[0]
            pos += 4

        pos = entry_end  # Skip any remaining bytes

        if enctype in _enctype_table:
            entries.append((principal, realm, kvno, enctype, Key(enctype, key_data)))
            print(f"  Keytab entry: {principal}@{realm} kvno={kvno} enctype={enctype} "
                  f"({len(key_data)*8}-bit key)")
        else:
            print(f"  Keytab entry (unsupported enctype {enctype}): "
                  f"{principal}@{realm} kvno={kvno}")

    if not entries:
        raise ValueError("No usable key entries found in keytab")
    return entries


# ─── TCP Reassembler ─────────────────────────────────────────────────────────

class TCPReassembler:
    """Track TCP segments per direction, deduplicate retransmissions, detect gaps."""

    def __init__(self):
        self.segments = []  # (seq, data)
        self._isn = None

    def add(self, seq, data):
        if not data:
            return
        if self._isn is None:
            self._isn = seq
        self.segments.append((seq, data))

    def reassemble(self):
        """Return (reassembled_bytes, gap_count)."""
        if not self.segments:
            return b'', 0

        # Sort by sequence number
        self.segments.sort(key=lambda x: x[0])

        # Build ordered, deduplicated byte ranges
        # Track (start_seq, end_seq, data)
        ranges = []
        for seq, data in self.segments:
            end = seq + len(data)
            # Check for overlap with existing ranges
            is_dup = False
            for rstart, rend, _ in ranges:
                if seq >= rstart and end <= rend:
                    is_dup = True
                    break
            if not is_dup:
                ranges.append((seq, end, data))

        # Sort by start sequence
        ranges.sort(key=lambda x: x[0])

        # Merge and detect gaps
        result = bytearray()
        gaps = 0
        expected_seq = ranges[0][0] if ranges else 0

        for rstart, rend, data in ranges:
            if rstart > expected_seq:
                gap_size = rstart - expected_seq
                gaps += 1
                # Fill gap with zeros (mark it)
                result.extend(b'\x00' * gap_size)
            elif rstart < expected_seq:
                # Overlapping retransmission — take only the new bytes
                overlap = expected_seq - rstart
                if overlap < len(data):
                    data = data[overlap:]
                else:
                    continue
            result.extend(data)
            expected_seq = max(expected_seq, rend)

        return bytes(result), gaps


# ─── Pcap/Pcapng Auto-detection ─────────────────────────────────────────────

def open_pcap(path):
    """Auto-detect pcap vs pcapng and return appropriate dpkt reader."""
    with open(path, 'rb') as f:
        magic = f.read(4)

    fh = open(path, 'rb')
    # pcapng magic: 0x0A0D0D0A (Section Header Block)
    if magic == b'\x0a\x0d\x0d\x0a':
        print(f"  Format: pcapng")
        return dpkt.pcapng.Reader(fh)
    # pcap magic: 0xA1B2C3D4 (big-endian) or 0xD4C3B2A1 (little-endian)
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
        print(f"  Format: pcap")
        return dpkt.pcap.Reader(fh)
    # pcap nanosecond: 0xA1B23C4D or 0x4D3CB2A1
    elif magic in (b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1'):
        print(f"  Format: pcap (nanosecond)")
        return dpkt.pcap.Reader(fh)
    else:
        # Try pcapng first, fall back to pcap
        fh.seek(0)
        try:
            reader = dpkt.pcapng.Reader(fh)
            print(f"  Format: pcapng (heuristic)")
            return reader
        except:
            fh.seek(0)
            print(f"  Format: pcap (heuristic)")
            return dpkt.pcap.Reader(fh)


# ─── Packet Extraction ──────────────────────────────────────────────────────

def extract_tcp_from_ipv4(raw):
    """Extract TCP fields from an IPv4 packet. Returns (src_ip, dst_ip, src_port, dst_port, seq, payload) or None."""
    try:
        ip = dpkt.ip.IP(raw)
        if ip.p != 6:  # Not TCP
            return None
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            return None
        src_ip = ip.src
        dst_ip = ip.dst
        payload = bytes(tcp.data) if tcp.data else b''
        return (src_ip, dst_ip, tcp.sport, tcp.dport, tcp.seq, payload)
    except:
        return None


def extract_tcp_from_ipv6(raw):
    """Extract TCP fields from an IPv6 packet (handles fixed header only).
    Returns (src_ip, dst_ip, src_port, dst_port, seq, payload) or None."""
    try:
        if len(raw) < 40:
            return None
        next_header = raw[6]
        payload_len = struct.unpack('>H', raw[4:6])[0]
        src_ip = raw[8:24]
        dst_ip = raw[24:40]

        # Walk extension headers to find TCP (protocol 6)
        offset = 40
        while next_header != 6:
            if next_header in (0, 43, 44, 50, 51, 60, 135):
                # Extension header: next_header(1) + length(1) + data
                if offset + 2 > len(raw):
                    return None
                next_header = raw[offset]
                ext_len = (raw[offset + 1] + 1) * 8
                offset += ext_len
            else:
                return None  # Unknown next header, not TCP

        tcp_data = raw[offset:]
        if len(tcp_data) < 20:
            return None
        sp = struct.unpack('>H', tcp_data[0:2])[0]
        dp = struct.unpack('>H', tcp_data[2:4])[0]
        seq = struct.unpack('>I', tcp_data[4:8])[0]
        doff = (tcp_data[12] >> 4) * 4
        td = tcp_data[doff:offset - 40 + payload_len]  # Trim to IPv6 payload length
        return (src_ip, dst_ip, sp, dp, seq, td)
    except:
        return None


# ─── Static Dictionary (MC-NBFS / WCF built-in) ─────────────────────────────
# Complete WCF ServiceModel static dictionary from ServiceModelStringsVersion1.cs
# (.NET Framework reference source). Keys are WIRE VALUES (even integers) as
# transmitted in MC-NBFX DictionaryString records. The wire value for logical
# index N is N*2.  See [MC-NBFS] section 2 for the authoritative table.
#
# DictionaryString encoding (MC-NBFSE section 2.2):
#   - Value is a MultiByteInt31 (mb32).
#   - EVEN values -> static dictionary at logical index value/2 (this table).
#   - ODD  values -> session dictionary (StringTable) at ID = value.
#     Session strings are assigned IDs 1, 3, 5, ... in order of appearance.
#
# Total: 487 entries (logical indices 0-486, wire values 0x000-0x3CC).

STATIC_DICT = {
    0x000: 'mustUnderstand',
    0x002: 'Envelope',
    0x004: 'http://www.w3.org/2003/05/soap-envelope',
    0x006: 'http://www.w3.org/2005/08/addressing',
    0x008: 'Header',
    0x00A: 'Action',
    0x00C: 'To',
    0x00E: 'Body',
    0x010: 'Algorithm',
    0x012: 'RelatesTo',
    0x014: 'http://www.w3.org/2005/08/addressing/anonymous',
    0x016: 'URI',
    0x018: 'Reference',
    0x01A: 'MessageID',
    0x01C: 'Id',
    0x01E: 'Identifier',
    0x020: 'http://schemas.xmlsoap.org/ws/2005/02/rm',
    0x022: 'Transforms',
    0x024: 'Transform',
    0x026: 'DigestMethod',
    0x028: 'DigestValue',
    0x02A: 'Address',
    0x02C: 'ReplyTo',
    0x02E: 'SequenceAcknowledgement',
    0x030: 'AcknowledgementRange',
    0x032: 'Upper',
    0x034: 'Lower',
    0x036: 'BufferRemaining',
    0x038: 'http://schemas.microsoft.com/ws/2006/05/rm',
    0x03A: 'http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement',
    0x03C: 'SecurityTokenReference',
    0x03E: 'Sequence',
    0x040: 'MessageNumber',
    0x042: 'http://www.w3.org/2000/09/xmldsig#',
    0x044: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
    0x046: 'KeyInfo',
    0x048: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    0x04A: 'http://www.w3.org/2001/04/xmlenc#',
    0x04C: 'http://schemas.xmlsoap.org/ws/2005/02/sc',
    0x04E: 'DerivedKeyToken',
    0x050: 'Nonce',
    0x052: 'Signature',
    0x054: 'SignedInfo',
    0x056: 'CanonicalizationMethod',
    0x058: 'SignatureMethod',
    0x05A: 'SignatureValue',
    0x05C: 'DataReference',
    0x05E: 'EncryptedData',
    0x060: 'EncryptionMethod',
    0x062: 'CipherData',
    0x064: 'CipherValue',
    0x066: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    0x068: 'Security',
    0x06A: 'Timestamp',
    0x06C: 'Created',
    0x06E: 'Expires',
    0x070: 'Length',
    0x072: 'ReferenceList',
    0x074: 'ValueType',
    0x076: 'Type',
    0x078: 'EncryptedHeader',
    0x07A: 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd',
    0x07C: 'RequestSecurityTokenResponseCollection',
    0x07E: 'http://schemas.xmlsoap.org/ws/2005/02/trust',
    0x080: 'http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret',
    0x082: 'http://schemas.microsoft.com/ws/2006/02/transactions',
    0x084: 's',
    0x086: 'Fault',
    0x088: 'MustUnderstand',
    0x08A: 'role',
    0x08C: 'relay',
    0x08E: 'Code',
    0x090: 'Reason',
    0x092: 'Text',
    0x094: 'Node',
    0x096: 'Role',
    0x098: 'Detail',
    0x09A: 'Value',
    0x09C: 'Subcode',
    0x09E: 'NotUnderstood',
    0x0A0: 'qname',
    0x0A2: '',
    0x0A4: 'From',
    0x0A6: 'FaultTo',
    0x0A8: 'EndpointReference',
    0x0AA: 'PortType',
    0x0AC: 'ServiceName',
    0x0AE: 'PortName',
    0x0B0: 'ReferenceProperties',
    0x0B2: 'RelationshipType',
    0x0B4: 'Reply',
    0x0B6: 'a',
    0x0B8: 'http://schemas.xmlsoap.org/ws/2006/02/addressingidentity',
    0x0BA: 'Identity',
    0x0BC: 'Spn',
    0x0BE: 'Upn',
    0x0C0: 'Rsa',
    0x0C2: 'Dns',
    0x0C4: 'X509v3Certificate',
    0x0C6: 'http://www.w3.org/2005/08/addressing/fault',
    0x0C8: 'ReferenceParameters',
    0x0CA: 'IsReferenceParameter',
    0x0CC: 'http://www.w3.org/2005/08/addressing/reply',
    0x0CE: 'http://www.w3.org/2005/08/addressing/none',
    0x0D0: 'Metadata',
    0x0D2: 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
    0x0D4: 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous',
    0x0D6: 'http://schemas.xmlsoap.org/ws/2004/08/addressing/fault',
    0x0D8: 'http://schemas.xmlsoap.org/ws/2004/06/addressingex',
    0x0DA: 'RedirectTo',
    0x0DC: 'Via',
    0x0DE: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    0x0E0: 'PrefixList',
    0x0E2: 'InclusiveNamespaces',
    0x0E4: 'ec',
    0x0E6: 'SecurityContextToken',
    0x0E8: 'Generation',
    0x0EA: 'Label',
    0x0EC: 'Offset',
    0x0EE: 'Properties',
    0x0F0: 'Cookie',
    0x0F2: 'wsc',
    0x0F4: 'http://schemas.xmlsoap.org/ws/2004/04/sc',
    0x0F6: 'http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk',
    0x0F8: 'http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct',
    0x0FA: 'http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT',
    0x0FC: 'http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT',
    0x0FE: 'RenewNeeded',
    0x100: 'BadContextToken',
    0x102: 'c',
    0x104: 'http://schemas.xmlsoap.org/ws/2005/02/sc/dk',
    0x106: 'http://schemas.xmlsoap.org/ws/2005/02/sc/sct',
    0x108: 'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT',
    0x10A: 'http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT',
    0x10C: 'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew',
    0x10E: 'http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew',
    0x110: 'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel',
    0x112: 'http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel',
    0x114: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
    0x116: 'http://www.w3.org/2001/04/xmlenc#kw-aes128',
    0x118: 'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
    0x11A: 'http://www.w3.org/2001/04/xmlenc#kw-aes192',
    0x11C: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    0x11E: 'http://www.w3.org/2001/04/xmlenc#kw-aes256',
    0x120: 'http://www.w3.org/2001/04/xmlenc#des-cbc',
    0x122: 'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
    0x124: 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
    0x126: 'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
    0x128: 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
    0x12A: 'http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1',
    0x12C: 'http://www.w3.org/2001/04/xmlenc#ripemd160',
    0x12E: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    0x130: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    0x132: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    0x134: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
    0x136: 'http://www.w3.org/2000/09/xmldsig#sha1',
    0x138: 'http://www.w3.org/2001/04/xmlenc#sha256',
    0x13A: 'http://www.w3.org/2001/04/xmlenc#sha512',
    0x13C: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
    0x13E: 'http://www.w3.org/2001/04/xmlenc#kw-tripledes',
    0x140: 'http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap',
    0x142: 'http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap',
    0x144: 'http://schemas.microsoft.com/ws/2006/05/security',
    0x146: 'dnse',
    0x148: 'o',
    0x14A: 'Password',
    0x14C: 'PasswordText',
    0x14E: 'Username',
    0x150: 'UsernameToken',
    0x152: 'BinarySecurityToken',
    0x154: 'EncodingType',
    0x156: 'KeyIdentifier',
    0x158: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary',
    0x15A: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary',
    0x15C: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text',
    0x15E: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier',
    0x160: 'http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ',
    0x162: 'http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510',
    0x164: 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID',
    0x166: 'Assertion',
    0x168: 'urn:oasis:names:tc:SAML:1.0:assertion',
    0x16A: 'http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license',
    0x16C: 'FailedAuthentication',
    0x16E: 'InvalidSecurityToken',
    0x170: 'InvalidSecurity',
    0x172: 'k',
    0x174: 'SignatureConfirmation',
    0x176: 'TokenType',
    0x178: 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1',
    0x17A: 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey',
    0x17C: 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1',
    0x17E: 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1',
    0x180: 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0',
    0x182: 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID',
    0x184: 'AUTH-HASH',
    0x186: 'RequestSecurityTokenResponse',
    0x188: 'KeySize',
    0x18A: 'RequestedTokenReference',
    0x18C: 'AppliesTo',
    0x18E: 'Authenticator',
    0x190: 'CombinedHash',
    0x192: 'BinaryExchange',
    0x194: 'Lifetime',
    0x196: 'RequestedSecurityToken',
    0x198: 'Entropy',
    0x19A: 'RequestedProofToken',
    0x19C: 'ComputedKey',
    0x19E: 'RequestSecurityToken',
    0x1A0: 'RequestType',
    0x1A2: 'Context',
    0x1A4: 'BinarySecret',
    0x1A6: 'http://schemas.xmlsoap.org/ws/2005/02/trust/spnego',
    0x1A8: 'http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego',
    0x1AA: 'wst',
    0x1AC: 'http://schemas.xmlsoap.org/ws/2004/04/trust',
    0x1AE: 'http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue',
    0x1B0: 'http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue',
    0x1B2: 'http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue',
    0x1B4: 'http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1',
    0x1B6: 'http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey',
    0x1B8: 'http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce',
    0x1BA: 'KeyType',
    0x1BC: 'http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey',
    0x1BE: 'http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey',
    0x1C0: 'Claims',
    0x1C2: 'InvalidRequest',
    0x1C4: 'RequestFailed',
    0x1C6: 'SignWith',
    0x1C8: 'EncryptWith',
    0x1CA: 'EncryptionAlgorithm',
    0x1CC: 'CanonicalizationAlgorithm',
    0x1CE: 'ComputedKeyAlgorithm',
    0x1D0: 'UseKey',
    0x1D2: 'http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego',
    0x1D4: 'http://schemas.microsoft.com/net/2004/07/secext/TLSNego',
    0x1D6: 't',
    0x1D8: 'http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue',
    0x1DA: 'http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue',
    0x1DC: 'http://schemas.xmlsoap.org/ws/2005/02/trust/Issue',
    0x1DE: 'http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey',
    0x1E0: 'http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1',
    0x1E2: 'http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce',
    0x1E4: 'RenewTarget',
    0x1E6: 'CancelTarget',
    0x1E8: 'RequestedTokenCancelled',
    0x1EA: 'RequestedAttachedReference',
    0x1EC: 'RequestedUnattachedReference',
    0x1EE: 'IssuedTokens',
    0x1F0: 'http://schemas.xmlsoap.org/ws/2005/02/trust/Renew',
    0x1F2: 'http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel',
    0x1F4: 'http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey',
    0x1F6: 'Access',
    0x1F8: 'AccessDecision',
    0x1FA: 'Advice',
    0x1FC: 'AssertionID',
    0x1FE: 'AssertionIDReference',
    0x200: 'Attribute',
    0x202: 'AttributeName',
    0x204: 'AttributeNamespace',
    0x206: 'AttributeStatement',
    0x208: 'AttributeValue',
    0x20A: 'Audience',
    0x20C: 'AudienceRestrictionCondition',
    0x20E: 'AuthenticationInstant',
    0x210: 'AuthenticationMethod',
    0x212: 'AuthenticationStatement',
    0x214: 'AuthorityBinding',
    0x216: 'AuthorityKind',
    0x218: 'AuthorizationDecisionStatement',
    0x21A: 'Binding',
    0x21C: 'Condition',
    0x21E: 'Conditions',
    0x220: 'Decision',
    0x222: 'DoNotCacheCondition',
    0x224: 'Evidence',
    0x226: 'IssueInstant',
    0x228: 'Issuer',
    0x22A: 'Location',
    0x22C: 'MajorVersion',
    0x22E: 'MinorVersion',
    0x230: 'NameIdentifier',
    0x232: 'Format',
    0x234: 'NameQualifier',
    0x236: 'Namespace',
    0x238: 'NotBefore',
    0x23A: 'NotOnOrAfter',
    0x23C: 'saml',
    0x23E: 'Statement',
    0x240: 'Subject',
    0x242: 'SubjectConfirmation',
    0x244: 'SubjectConfirmationData',
    0x246: 'ConfirmationMethod',
    0x248: 'urn:oasis:names:tc:SAML:1.0:cm:holder-of-key',
    0x24A: 'urn:oasis:names:tc:SAML:1.0:cm:sender-vouches',
    0x24C: 'SubjectLocality',
    0x24E: 'DNSAddress',
    0x250: 'IPAddress',
    0x252: 'SubjectStatement',
    0x254: 'urn:oasis:names:tc:SAML:1.0:am:unspecified',
    0x256: 'xmlns',
    0x258: 'Resource',
    0x25A: 'UserName',
    0x25C: 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
    0x25E: 'EmailName',
    0x260: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    0x262: 'u',
    0x264: 'ChannelInstance',
    0x266: 'http://schemas.microsoft.com/ws/2005/02/duplex',
    0x268: 'Encoding',
    0x26A: 'MimeType',
    0x26C: 'CarriedKeyName',
    0x26E: 'Recipient',
    0x270: 'EncryptedKey',
    0x272: 'KeyReference',
    0x274: 'e',
    0x276: 'http://www.w3.org/2001/04/xmlenc#Element',
    0x278: 'http://www.w3.org/2001/04/xmlenc#Content',
    0x27A: 'KeyName',
    0x27C: 'MgmtData',
    0x27E: 'KeyValue',
    0x280: 'RSAKeyValue',
    0x282: 'Modulus',
    0x284: 'Exponent',
    0x286: 'X509Data',
    0x288: 'X509IssuerSerial',
    0x28A: 'X509IssuerName',
    0x28C: 'X509SerialNumber',
    0x28E: 'X509Certificate',
    0x290: 'AckRequested',
    0x292: 'http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested',
    0x294: 'AcksTo',
    0x296: 'Accept',
    0x298: 'CreateSequence',
    0x29A: 'http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence',
    0x29C: 'CreateSequenceRefused',
    0x29E: 'CreateSequenceResponse',
    0x2A0: 'http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse',
    0x2A2: 'FaultCode',
    0x2A4: 'InvalidAcknowledgement',
    0x2A6: 'LastMessage',
    0x2A8: 'http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage',
    0x2AA: 'LastMessageNumberExceeded',
    0x2AC: 'MessageNumberRollover',
    0x2AE: 'Nack',
    0x2B0: 'netrm',
    0x2B2: 'Offer',
    0x2B4: 'r',
    0x2B6: 'SequenceFault',
    0x2B8: 'SequenceTerminated',
    0x2BA: 'TerminateSequence',
    0x2BC: 'http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence',
    0x2BE: 'UnknownSequence',
    0x2C0: 'http://schemas.microsoft.com/ws/2006/02/tx/oletx',
    0x2C2: 'oletx',
    0x2C4: 'OleTxTransaction',
    0x2C6: 'PropagationToken',
    0x2C8: 'http://schemas.xmlsoap.org/ws/2004/10/wscoor',
    0x2CA: 'wscoor',
    0x2CC: 'CreateCoordinationContext',
    0x2CE: 'CreateCoordinationContextResponse',
    0x2D0: 'CoordinationContext',
    0x2D2: 'CurrentContext',
    0x2D4: 'CoordinationType',
    0x2D6: 'RegistrationService',
    0x2D8: 'Register',
    0x2DA: 'RegisterResponse',
    0x2DC: 'ProtocolIdentifier',
    0x2DE: 'CoordinatorProtocolService',
    0x2E0: 'ParticipantProtocolService',
    0x2E2: 'http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext',
    0x2E4: 'http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse',
    0x2E6: 'http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register',
    0x2E8: 'http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse',
    0x2EA: 'http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault',
    0x2EC: 'ActivationCoordinatorPortType',
    0x2EE: 'RegistrationCoordinatorPortType',
    0x2F0: 'InvalidState',
    0x2F2: 'InvalidProtocol',
    0x2F4: 'InvalidParameters',
    0x2F6: 'NoActivity',
    0x2F8: 'ContextRefused',
    0x2FA: 'AlreadyRegistered',
    0x2FC: 'http://schemas.xmlsoap.org/ws/2004/10/wsat',
    0x2FE: 'wsat',
    0x300: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion',
    0x302: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC',
    0x304: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC',
    0x306: 'Prepare',
    0x308: 'Prepared',
    0x30A: 'ReadOnly',
    0x30C: 'Commit',
    0x30E: 'Rollback',
    0x310: 'Committed',
    0x312: 'Aborted',
    0x314: 'Replay',
    0x316: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit',
    0x318: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback',
    0x31A: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed',
    0x31C: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted',
    0x31E: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare',
    0x320: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared',
    0x322: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly',
    0x324: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay',
    0x326: 'http://schemas.xmlsoap.org/ws/2004/10/wsat/fault',
    0x328: 'CompletionCoordinatorPortType',
    0x32A: 'CompletionParticipantPortType',
    0x32C: 'CoordinatorPortType',
    0x32E: 'ParticipantPortType',
    0x330: 'InconsistentInternalState',
    0x332: 'mstx',
    0x334: 'Enlistment',
    0x336: 'protocol',
    0x338: 'LocalTransactionId',
    0x33A: 'IsolationLevel',
    0x33C: 'IsolationFlags',
    0x33E: 'Description',
    0x340: 'Loopback',
    0x342: 'RegisterInfo',
    0x344: 'ContextId',
    0x346: 'TokenId',
    0x348: 'AccessDenied',
    0x34A: 'InvalidPolicy',
    0x34C: 'CoordinatorRegistrationFailed',
    0x34E: 'TooManyEnlistments',
    0x350: 'Disabled',
    0x352: 'ActivityId',
    0x354: 'http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics',
    0x356: 'http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1',
    0x358: 'http://schemas.xmlsoap.org/ws/2002/12/policy',
    0x35A: 'FloodMessage',
    0x35C: 'LinkUtility',
    0x35E: 'Hops',
    0x360: 'http://schemas.microsoft.com/net/2006/05/peer/HopCount',
    0x362: 'PeerVia',
    0x364: 'http://schemas.microsoft.com/net/2006/05/peer',
    0x366: 'PeerFlooder',
    0x368: 'PeerTo',
    0x36A: 'http://schemas.microsoft.com/ws/2005/05/routing',
    0x36C: 'PacketRoutable',
    0x36E: 'http://schemas.microsoft.com/ws/2005/05/addressing/none',
    0x370: 'http://schemas.microsoft.com/ws/2005/05/envelope/none',
    0x372: 'http://www.w3.org/2001/XMLSchema-instance',
    0x374: 'http://www.w3.org/2001/XMLSchema',
    0x376: 'nil',
    0x378: 'type',
    0x37A: 'char',
    0x37C: 'boolean',
    0x37E: 'byte',
    0x380: 'unsignedByte',
    0x382: 'short',
    0x384: 'unsignedShort',
    0x386: 'int',
    0x388: 'unsignedInt',
    0x38A: 'long',
    0x38C: 'unsignedLong',
    0x38E: 'float',
    0x390: 'double',
    0x392: 'decimal',
    0x394: 'dateTime',
    0x396: 'string',
    0x398: 'base64Binary',
    0x39A: 'anyType',
    0x39C: 'duration',
    0x39E: 'guid',
    0x3A0: 'anyURI',
    0x3A2: 'QName',
    0x3A4: 'time',
    0x3A6: 'date',
    0x3A8: 'hexBinary',
    0x3AA: 'gYearMonth',
    0x3AC: 'gYear',
    0x3AE: 'gMonthDay',
    0x3B0: 'gDay',
    0x3B2: 'gMonth',
    0x3B4: 'integer',
    0x3B6: 'positiveInteger',
    0x3B8: 'negativeInteger',
    0x3BA: 'nonPositiveInteger',
    0x3BC: 'nonNegativeInteger',
    0x3BE: 'normalizedString',
    0x3C0: 'ConnectionLimitReached',
    0x3C2: 'http://schemas.xmlsoap.org/soap/envelope/',
    0x3C4: 'actor',
    0x3C6: 'faultcode',
    0x3C8: 'faultstring',
    0x3CA: 'faultactor',
    0x3CC: 'detail',
}


# ─── MC-NBFX Binary XML Decoder ─────────────────────────────────────────────

class NBFXDecoder:
    def __init__(self, data, session_dict=None):
        self.data = data
        self.pos = 0
        self.parts = []
        self.stack = []
        self.session_dict = session_dict or {}

    def read_byte(self):
        if self.pos >= len(self.data):
            raise EOFError()
        b = self.data[self.pos]; self.pos += 1
        return b

    def read_bytes(self, n):
        if self.pos + n > len(self.data):
            raise EOFError()
        r = self.data[self.pos:self.pos + n]; self.pos += n
        return r

    def read_mb32(self):
        result = 0; shift = 0
        while True:
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        return result

    def read_string(self):
        length = self.read_mb32()
        return self.read_bytes(length).decode('utf-8', errors='replace')

    def dict_string(self, idx):
        """Resolve a DictionaryString wire value.

        Per MC-NBFSE section 2.2:
          - EVEN values -> static dictionary (MC-NBFS), key = wire value.
          - ODD  values -> session dictionary (StringTable), key = wire value.
        """
        if idx & 1:  # odd -> session dictionary
            return self.session_dict.get(idx, f'[session:{idx}]')
        else:  # even -> static dictionary
            return STATIC_DICT.get(idx, f'[static:{idx}]')

    def emit(self, text):
        self.parts.append(text)

    def decode(self):
        try:
            while self.pos < len(self.data):
                self._decode_record()
        except EOFError:
            pass
        except Exception as e:
            self.emit(f'[error:{e}]')
        return ''.join(self.parts)

    def _decode_record(self):
        rt = self.read_byte()

        # EndElement
        if rt == 0x01:
            if self.stack:
                self.emit(f'</{self.stack.pop()}>')
            return

        # Comment
        if rt == 0x02:
            self.emit(f'<!-- {self.read_string()} -->')
            return

        # Array (not fully implemented - skip)
        if rt == 0x03:
            self.emit('[array]')
            return

        # Element records
        if rt == 0x40:  # ShortElement
            name = self.read_string()
            self._open_element(name)
            return
        if rt == 0x41:  # Element
            prefix = self.read_string()
            name = self.read_string()
            self._open_element(f'{prefix}:{name}' if prefix else name)
            return
        if rt == 0x42:  # ShortDictionaryElement
            self._open_element(self.dict_string(self.read_mb32()))
            return
        if rt == 0x43:  # DictionaryElement
            prefix = self.read_string()
            name = self.dict_string(self.read_mb32())
            self._open_element(f'{prefix}:{name}' if prefix else name)
            return

        # PrefixDictionaryElement a-z: 0x44-0x5D (sequential)
        if 0x44 <= rt <= 0x5D:
            prefix = chr(ord('a') + rt - 0x44)
            name = self.dict_string(self.read_mb32())
            self._open_element(f'{prefix}:{name}')
            return

        # PrefixElement a-z: 0x5E-0x77 (sequential)
        if 0x5E <= rt <= 0x77:
            prefix = chr(ord('a') + rt - 0x5E)
            name = self.read_string()
            self._open_element(f'{prefix}:{name}')
            return

        # Text records: 0x80+
        if rt >= 0x80:
            value, is_end = self._read_text_value(rt)
            self.emit(value)
            if is_end and self.stack:
                self.emit(f'</{self.stack.pop()}>')
            return

        self.emit(f'[rec:{rt:#04x}]')

    def _open_element(self, tag):
        self.stack.append(tag)
        self.emit(f'<{tag}')
        self._read_attributes()
        self.emit('>')

    def _read_attributes(self):
        while self.pos < len(self.data):
            rt = self.data[self.pos]

            if rt == 0x04:  # ShortAttribute
                self.pos += 1
                name = self.read_string()
                self.emit(f' {name}="'); self._read_attr_value(); self.emit('"')
            elif rt == 0x05:  # Attribute
                self.pos += 1
                p = self.read_string(); n = self.read_string()
                self.emit(f' {p}:{n}="'); self._read_attr_value(); self.emit('"')
            elif rt == 0x06:  # ShortDictionaryAttribute
                self.pos += 1
                n = self.dict_string(self.read_mb32())
                self.emit(f' {n}="'); self._read_attr_value(); self.emit('"')
            elif rt == 0x07:  # DictionaryAttribute
                self.pos += 1
                p = self.read_string(); n = self.dict_string(self.read_mb32())
                self.emit(f' {p}:{n}="'); self._read_attr_value(); self.emit('"')
            elif rt == 0x08:  # ShortXmlnsAttribute
                self.pos += 1
                self.emit(f' xmlns="{self.read_string()}"')
            elif rt == 0x09:  # XmlnsAttribute
                self.pos += 1
                p = self.read_string(); u = self.read_string()
                self.emit(f' xmlns:{p}="{u}"')
            elif rt == 0x0A:  # ShortDictionaryXmlnsAttribute
                self.pos += 1
                self.emit(f' xmlns="{self.dict_string(self.read_mb32())}"')
            elif rt == 0x0B:  # DictionaryXmlnsAttribute
                self.pos += 1
                p = self.read_string()
                self.emit(f' xmlns:{p}="{self.dict_string(self.read_mb32())}"')
            elif 0x0C <= rt <= 0x25:
                # PrefixDictionaryAttribute a-m (sequential)
                self.pos += 1
                prefix = chr(ord('a') + rt - 0x0C)
                n = self.dict_string(self.read_mb32())
                self.emit(f' {prefix}:{n}="'); self._read_attr_value(); self.emit('"')
            elif 0x26 <= rt <= 0x3F:
                # PrefixAttribute a-m (sequential)
                self.pos += 1
                prefix = chr(ord('a') + rt - 0x26)
                n = self.read_string()
                self.emit(f' {prefix}:{n}="'); self._read_attr_value(); self.emit('"')
            else:
                break

    def _read_attr_value(self):
        rt = self.read_byte()
        if rt >= 0x80:
            value, _ = self._read_text_value(rt)
            self.emit(value)
        else:
            self.emit(f'[aval:{rt:#04x}]')

    def _read_text_value(self, rt):
        is_end = rt & 1
        base = rt & ~1
        v = self._decode_text(base)
        return v, is_end

    def _decode_text(self, base):
        # Text record types from .NET XmlBinaryNodeType (dotnet/runtime source).
        # NOTE: These differ significantly from the MC-NBFX open specification!
        # The open spec places UniqueIdText at 0x9E; the actual .NET impl puts it
        # at 0xAC.  The full mapping was verified against XmlBinaryNodeType.cs in
        # src/libraries/System.Private.DataContractSerialization/src/System/Xml/.
        if base == 0x80: return '0'                          # ZeroText
        if base == 0x82: return '1'                          # OneText
        if base == 0x84: return 'false'                      # FalseText
        if base == 0x86: return 'true'                       # TrueText
        if base == 0x88:                                     # Int8Text
            return str(struct.unpack('<b', self.read_bytes(1))[0])
        if base == 0x8A:                                     # Int16Text
            return str(struct.unpack('<h', self.read_bytes(2))[0])
        if base == 0x8C:                                     # Int32Text
            return str(struct.unpack('<i', self.read_bytes(4))[0])
        if base == 0x8E:                                     # Int64Text
            return str(struct.unpack('<q', self.read_bytes(8))[0])
        if base == 0x90:                                     # FloatText
            return str(struct.unpack('<f', self.read_bytes(4))[0])
        if base == 0x92:                                     # DoubleText
            return str(struct.unpack('<d', self.read_bytes(8))[0])
        if base == 0x94:                                     # DecimalText
            self.read_bytes(16); return '[decimal]'
        if base == 0x96:                                     # DateTimeText
            raw = struct.unpack('<Q', self.read_bytes(8))[0]
            ticks = raw & 0x3FFFFFFFFFFFFFFF
            try:
                import datetime
                epoch = datetime.datetime(1, 1, 1)
                dt = epoch + datetime.timedelta(microseconds=ticks // 10)
                return dt.isoformat()
            except:
                return '[datetime]'
        if base == 0x98:                                     # Chars8Text
            return self.read_bytes(self.read_byte()).decode('utf-8', errors='replace')
        if base == 0x9A:                                     # Chars16Text
            return self.read_bytes(struct.unpack('<H', self.read_bytes(2))[0]).decode('utf-8', errors='replace')
        if base == 0x9C:                                     # Chars32Text
            return self.read_bytes(struct.unpack('<I', self.read_bytes(4))[0]).decode('utf-8', errors='replace')
        if base == 0x9E:                                     # Bytes8Text
            return base64.b64encode(self.read_bytes(self.read_byte())).decode()
        if base == 0xA0:                                     # Bytes16Text
            return base64.b64encode(self.read_bytes(struct.unpack('<H', self.read_bytes(2))[0])).decode()
        if base == 0xA2:                                     # Bytes32Text
            return base64.b64encode(self.read_bytes(struct.unpack('<I', self.read_bytes(4))[0])).decode()
        if base == 0xA4: return ''                           # StartListText
        if base == 0xA6: return ''                           # EndListText
        if base == 0xA8: return ''                           # EmptyText
        if base == 0xAA:                                     # DictionaryText
            return self.dict_string(self.read_mb32())
        if base == 0xAC:                                     # UniqueIdText
            return f'urn:uuid:{uuid.UUID(bytes_le=self.read_bytes(16))}'
        if base == 0xAE:                                     # TimeSpanText
            val = struct.unpack('<q', self.read_bytes(8))[0]
            return f'PT{val/10000000:.0f}S'
        if base == 0xB0:                                     # GuidText
            return str(uuid.UUID(bytes_le=self.read_bytes(16)))
        if base == 0xB2:                                     # UInt64Text
            return str(struct.unpack('<Q', self.read_bytes(8))[0])
        if base == 0xB4:                                     # BoolText
            return 'true' if self.read_byte() else 'false'
        if base == 0xB6:                                     # UnicodeChars8Text
            return self.read_bytes(self.read_byte()).decode('utf-16-le', errors='replace')
        if base == 0xB8:                                     # UnicodeChars16Text
            return self.read_bytes(struct.unpack('<H', self.read_bytes(2))[0]).decode('utf-16-le', errors='replace')
        if base == 0xBA:                                     # UnicodeChars32Text
            return self.read_bytes(struct.unpack('<I', self.read_bytes(4))[0]).decode('utf-16-le', errors='replace')
        if base == 0xBC:                                     # QNameDictionaryText
            pi = self.read_byte()
            ni = self.read_mb32()
            p = chr(ord('a') + pi) if pi < 26 else f'ns{pi}'
            return f'{p}:{self.dict_string(ni)}'
        return f'[text:{base:#04x}]'


# ─── Helpers ──────────────────────────────────────────────────────────────────

def read_mb32(data, offset):
    result = 0; shift = 0
    while offset < len(data):
        b = data[offset]; offset += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return result, offset


def decrypt_gss_wrap_cfx(token_data, key, is_acceptor):
    if len(token_data) < 17 or token_data[:2] != b'\x05\x04':
        return None
    if token_data[3] != 0xFF or not (token_data[2] & 0x02):
        return None
    rrc = struct.unpack('>H', token_data[6:8])[0]
    ct = token_data[16:]
    if rrc > 0 and len(ct) > 0:
        r = rrc % len(ct)
        ct = ct[r:] + ct[:r]
    ku = 22 if is_acceptor else 24
    return _enctype_table[key.enctype].decrypt(key, ku, ct)[:-16]


def _find_all_positions(data, markers):
    """Find all positions of any marker bytes in data, sorted by position."""
    positions = []
    for marker in markers:
        start = 0
        while True:
            pos = data.find(marker, start)
            if pos < 0:
                break
            positions.append(pos)
            start = pos + 1
    positions.sort()
    return positions


def extract_keys(c2s, s2c, keytab_entries):
    """Try each keytab entry to decrypt the Kerberos ticket.
    Returns (session_key, client_subkey, server_subkey, principal) or raises."""

    # Find ALL candidate AP-REQ positions (tag 0x6e = APPLICATION 14 constructed)
    # with various BER length encodings (0x81=1-byte, 0x82=2-byte, 0x83=3-byte)
    apreq_markers = [b'\x6e\x82', b'\x6e\x81', b'\x6e\x83']
    apreq_positions = _find_all_positions(c2s, apreq_markers)
    if not apreq_positions:
        raise ValueError("AP-REQ not found")

    # AP-REP markers (tag 0x6f = APPLICATION 15 constructed)
    aprep_markers = [b'\x6f\x81', b'\x6f\x82', b'\x6f\x83']

    # Try each candidate AP-REQ position
    last_error = None
    for pos in apreq_positions:
        try:
            apreq = AP_REQ.load(c2s[pos:])
        except Exception:
            continue  # False positive — not a valid AP-REQ at this offset

        ticket_cipher = bytes(apreq['ticket']['enc-part']['cipher'])
        ticket_etype = int(apreq['ticket']['enc-part']['etype'])

        # Try each keytab entry that matches the enctype
        for princ_name, realm, kvno, enctype, host_key in keytab_entries:
            if enctype != ticket_etype:
                continue
            try:
                cs = _enctype_table[enctype]
                ticket_pt = cs.decrypt(host_key, 2, ticket_cipher)
                et = EncTicketPart.load(ticket_pt)
                sk = Key(int(et['key']['keytype']), bytes(et['key']['keyvalue']))

                auth_pt = cs.decrypt(sk, 11, bytes(apreq['authenticator']['cipher']))
                auth = Authenticator.load(auth_pt)
                csk = None
                if auth['subkey'] is not None and auth['subkey'].native is not None:
                    csk = Key(int(auth['subkey']['keytype']), bytes(auth['subkey']['keyvalue']))
                principal = '/'.join(str(s) for s in auth['cname']['name-string']) + '@' + str(auth['crealm'])

                # Find AP-REP — try all candidate positions
                aprep_positions = _find_all_positions(s2c, aprep_markers)
                if not aprep_positions:
                    raise ValueError("AP-REP not found")
                aprep_ok = False
                for pos2 in aprep_positions:
                    try:
                        aprep = AP_REP.load(s2c[pos2:])
                        aprep_pt = cs.decrypt(sk, 12, bytes(aprep['enc-part']['cipher']))
                        ea = EncAPRepPart.load(aprep_pt)
                        ssk = sk
                        if ea['subkey'] is not None and ea['subkey'].native is not None:
                            ssk = Key(int(ea['subkey']['keytype']), bytes(ea['subkey']['keyvalue']))
                        return sk, csk, ssk, principal
                    except Exception:
                        continue
                raise ValueError("AP-REP found but could not be decrypted")
            except Exception as e:
                last_error = e
                continue

    if last_error:
        raise ValueError(f"No keytab entry could decrypt the ticket (last error: {last_error})")
    raise ValueError("No keytab entry matches any ticket enctype found")


def parse_ns_frames(data, is_c2s):
    offset = 0
    if is_c2s:
        while offset < len(data):
            rt = data[offset]
            if rt == 0x00: offset += 3
            elif rt == 0x01: offset += 2
            elif rt == 0x02: offset += 2 + data[offset + 1]
            elif rt == 0x03: offset += 2
            elif rt == 0x09: offset += 2 + data[offset + 1]; break
            else: break
    else:
        if data[0] == 0x0A: offset = 1
    while offset < len(data):
        s = data[offset]
        if s not in (0x14, 0x15, 0x16): break
        if offset + 5 > len(data): break
        plen = struct.unpack('>H', data[offset + 3:offset + 5])[0]
        offset += 5 + plen
    frames = []
    while offset + 4 <= len(data):
        flen = struct.unpack('<I', data[offset:offset + 4])[0]
        if flen == 0 or flen > 10_000_000 or offset + 4 + flen > len(data): break
        frames.append(data[offset + 4:offset + 4 + flen])
        offset += 4 + flen
    return frames


def parse_nmf_envelope(payload, session_dict):
    """Parse MC-NBFSE envelope: string table (byte-counted) + Binary XML.

    Per MC-NBFSE section 2.1, session dictionary strings are assigned ODD IDs
    starting at 1, incrementing by 2 (1, 3, 5, 7, ...).  The static dictionary
    uses EVEN IDs.  We track the next available odd ID across all envelopes in
    a connection so that subsequent StringTables continue the numbering.
    """
    pos = 0
    table_bytes, pos = read_mb32(payload, pos)
    tbl_end = pos + table_bytes

    # Determine next odd session ID.  If the session_dict already has entries
    # pick the next odd number after the highest existing key.
    if session_dict:
        next_idx = max(session_dict.keys()) + 2  # odd + 2 = next odd
    else:
        next_idx = 1  # first session string = ID 1

    while pos < tbl_end and pos < len(payload):
        slen, pos = read_mb32(payload, pos)
        if pos + slen > len(payload):
            break
        s = payload[pos:pos + slen].decode('utf-8', errors='replace')
        session_dict[next_idx] = s
        next_idx += 2  # odd IDs: 1, 3, 5, 7, ...
        pos += slen

    xml_data = payload[tbl_end:]
    decoder = NBFXDecoder(xml_data, session_dict)
    return decoder.decode(), session_dict


def parse_nmf_records(stream, session_dict):
    """Parse .NET Message Framing Sized Envelopes from the decrypted stream."""
    messages = []
    offset = 0
    while offset < len(stream):
        rt = stream[offset]; offset += 1
        if rt in (0x0A, 0x0B, 0x0C):
            continue
        if rt == 0x06:  # Sized Envelope
            sz, offset = read_mb32(stream, offset)
            end = min(offset + sz, len(stream))
            payload = stream[offset:end]
            offset = end
            if payload:
                xml, session_dict = parse_nmf_envelope(payload, session_dict)
                if xml.strip():
                    messages.append(xml)
        elif rt == 0x07:  # End
            pass
        else:
            break
    return messages


# ─── ADWS Port Detection ────────────────────────────────────────────────────

def is_nmf_preamble(data):
    """Check if data starts with .NET Message Framing version record."""
    return len(data) >= 3 and data[0] == 0x00 and data[1] == 0x01 and data[2] == 0x00


def detect_adws_ports(packets):
    """Scan packets for .NET Message Framing preambles to find ADWS ports.
    Returns set of destination ports that received NMF preambles."""
    ports = set()
    for src_ip, dst_ip, sp, dp, seq, payload in packets:
        if payload and is_nmf_preamble(payload):
            # Check for ADWS via string in preamble
            if b'ActiveDirectoryWebServices' in payload or b'net.tcp://' in payload:
                ports.add(dp)
    return ports


# ─── Security Descriptor → SDDL Converter ────────────────────────────────────

# Well-known SID → SDDL abbreviation mapping
# See: https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
_WELLKNOWN_SIDS = {
    'S-1-0-0':   'WD',  # used sometimes, but WD is really S-1-1-0
    'S-1-1-0':   'WD',  # World / Everyone
    'S-1-3-0':   'CO',  # Creator Owner
    'S-1-3-1':   'CG',  # Creator Group
    'S-1-5-1':   'DU',  # Dialup — reuse note: DU also used for Domain Users (RID-relative)
    'S-1-5-2':   'NU',  # Network
    'S-1-5-4':   'IU',  # Interactive
    'S-1-5-6':   'SU',  # Service
    'S-1-5-7':   'AN',  # Anonymous
    'S-1-5-9':   'ED',  # Enterprise Domain Controllers
    'S-1-5-10':  'PS',  # Principal Self
    'S-1-5-11':  'AU',  # Authenticated Users
    'S-1-5-12':  'RC',  # Restricted Code
    'S-1-5-18':  'SY',  # Local System
    'S-1-5-19':  'LS',  # Local Service
    'S-1-5-20':  'NS',  # Network Service
    'S-1-5-32-544': 'BA',  # Builtin Administrators
    'S-1-5-32-545': 'BU',  # Builtin Users
    'S-1-5-32-546': 'BG',  # Builtin Guests
    'S-1-5-32-547': 'PU',  # Power Users
    'S-1-5-32-548': 'AO',  # Account Operators
    'S-1-5-32-549': 'SO',  # Server Operators
    'S-1-5-32-550': 'PO',  # Print Operators
    'S-1-5-32-551': 'BO',  # Backup Operators
    'S-1-5-32-552': 'RE',  # Replicator
    'S-1-5-32-554': 'RU',  # Pre-Windows 2000 Compatible Access
    'S-1-5-32-555': 'RD',  # Remote Desktop Users
    'S-1-5-32-556': 'NO',  # Network Configuration Operators
    'S-1-5-32-558': 'MU',  # Performance Monitor Users
    'S-1-5-32-559': 'LU',  # Performance Log Users
    'S-1-5-32-568': 'IS',  # IIS_IUSRS
    'S-1-5-32-569': 'CY',  # Crypto Operators
    'S-1-5-32-573': 'ER',  # Event Log Readers
    'S-1-5-32-574': 'CD',  # Certificate Service DCOM Access
    'S-1-5-32-575': 'RA',  # RDS Remote Access Servers
    'S-1-5-32-576': 'ES',  # RDS Endpoint Servers
    'S-1-5-32-577': 'MS',  # RDS Management Servers
    'S-1-5-32-578': 'HA',  # Hyper-V Administrators
    'S-1-5-32-579': 'AA',  # Access Control Assistance Operators
    'S-1-5-32-580': 'RM',  # Remote Management Users
    'S-1-15-2-1': 'AC',  # All App Packages
}

# Domain-relative RID → SDDL abbreviation
_DOMAIN_RID_SDDL = {
    500: 'LA',  # Administrator
    501: 'LG',  # Guest
    512: 'DA',  # Domain Admins
    513: 'DU',  # Domain Users
    514: 'DG',  # Domain Guests
    515: 'DC',  # Domain Computers
    516: 'DD',  # Domain Controllers
    517: 'CA',  # Cert Publishers
    518: 'SA',  # Schema Admins
    519: 'EA',  # Enterprise Admins
    520: 'PA',  # Group Policy Creator Owners
    521: 'RO',  # Read-only Domain Controllers
    522: 'CN',  # Cloneable Domain Controllers
    526: 'AP',  # Key Admins
    527: 'KA',  # Enterprise Key Admins
    553: 'RS',  # RAS and IAS Servers
}

# Common AD extended rights / property set / schema class GUIDs
_AD_GUIDS = {
    '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f': 'Reanimate-Tombstones',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Synchronize',
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Manage-Topology',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    'ab721a52-1e2f-11d0-9819-00aa0040529b': 'Domain-Administer-Server',
    'ab721a53-1e2f-11d0-9819-00aa0040529b': 'User-Change-Password',
    'ab721a54-1e2f-11d0-9819-00aa0040529b': 'Send-As',
    'ab721a56-1e2f-11d0-9819-00aa0040529b': 'Receive-As',
    'ab721a55-1e2f-11d0-9819-00aa0040529b': 'Send-To',
    '00000000-0000-0000-0000-000000000000': '<All>',
    'e48d0154-bcf8-11d1-8702-00c04fb96050': 'Public-Information',
    'b8119fd0-04f6-4762-ab7a-4986c76b3f9a': 'Domain-Other-Parameters',
    'c7407360-20bf-11d0-a768-00aa006e0529': 'Domain-Password',
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf': 'General-Information',
    'bc0ac240-79a9-11d0-9020-00c04fc2d3cf': 'Membership',
    'bf967a86-0de6-11d0-a285-00aa003049e2': 'Computer',
    'bf967a9c-0de6-11d0-a285-00aa003049e2': 'Group',
    'bf967aba-0de6-11d0-a285-00aa003049e2': 'User',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'User-Account-Restrictions',
    '5f202010-79a5-11d0-9020-00c04fc2d3cf': 'User-Logon',
    '77b5b886-944a-11d1-aebd-0000f80367c1': 'Personal-Information',
    'e45795b2-9455-11d1-aebd-0000f80367c1': 'Email-Information',
    'e45795b3-9455-11d1-aebd-0000f80367c1': 'Web-Information',
    '037088f8-0ae1-11d2-b422-00a0c968f939': 'RAS-Information',
    'ffa6f046-ca4b-4feb-b40d-04dfee722543': 'ms-TPM-Tpm-Information-For-Computer',
    '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'ms-DS-Key-Credential-Link',
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8': 'Private-Information',
    '72e39547-7b18-11d1-adef-00c04fd8d5cd': 'DNS-Host-Name-Attributes',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Validated-SPN',
    'd31a8757-2447-4545-8081-3bb610cacbf2': 'Validated-MS-DS-Behavior-Version',
    '9b026da6-0d3c-465c-8bee-5199d7165cba': 'Validated-MS-DS-Additional-DNS-Host-Name',
    '80863791-dbe9-4eb8-837e-7f0ab55d9ac7': 'Validated-DNS-Host-Name',
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc': 'Allowed-To-Authenticate',
    'edacfd8f-ffb3-11d1-b41d-00a0c968f939': 'Apply-Group-Policy',
    '037088f8-0ae1-11d2-b422-00a0c968f939': 'RAS-Information',
    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501': 'Unexpire-Password',
    'ba33815a-4f93-4c76-87f3-57574bff8109': 'Migrate-SID-History',
    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Planning',
    'b7b1b3de-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Logging',
    '9923a32a-3607-11d2-b9be-0000f87a36b2': 'DS-Install-Replica',
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd': 'Change-Infrastructure-Master',
    'be2bb760-7f46-11d2-b9ad-00c04f79f805': 'Update-Schema-Cache',
    'fec364e0-0a98-11d1-adbb-00c04fd8d5cd': 'Recalculate-Hierarchy',
    '0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Recalculate-Security-Inheritance',
    '014bf69c-7b3b-11d1-85f6-08002be74fab': 'Change-Schema-Master',
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd': 'Change-PDC',
    'bae50096-4752-11d1-9052-00c04fc2d4cf': 'Change-Rid-Master',
    '440820ad-65b4-11d1-a3da-0000f875ae0d': 'Add-GUID',
    '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd': 'Allocate-Rids',
    '4b6e08c0-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-Dead-Letter',
    '4b6e08c1-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-Dead-Letter',
    '4b6e08c2-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-computer-Journal',
    '4b6e08c3-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-computer-Journal',
    '06bd3200-df3e-11d1-9c86-006008764d0e': 'msmq-Receive',
    '06bd3201-df3e-11d1-9c86-006008764d0e': 'msmq-Peek',
    '06bd3202-df3e-11d1-9c86-006008764d0e': 'msmq-Send',
    '06bd3203-df3e-11d1-9c86-006008764d0e': 'msmq-Receive-journal',
    'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open-Address-Book',
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2': 'Read-Only-Replication-Secret-Synchronization',
    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f': 'Run-Protect-Admin-Groups-Task',
    '7c0e2a7c-a419-48e4-a995-10180aad54dd': 'Manage-Optional-Features',
    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e': 'DS-Clone-Domain-Controller',
    '2f16c4a5-b98e-432c-952a-cb388ba33f2e': 'DS-Set-Owner',
    '9b026da6-0d3c-465c-8bee-5199d7165cba': 'DS-Validated-Write-Computer',
    'e362ed86-b728-0842-b27d-2dea7a9df218': 'MS-DS-Read-Default-Security-Descriptor',
}


def _sid_to_string(data, offset):
    """Parse a binary SID at offset, return (sid_string, bytes_consumed)."""
    if offset + 2 > len(data):
        return None, 0
    revision = data[offset]
    sub_count = data[offset + 1]
    if offset + 8 + sub_count * 4 > len(data):
        return None, 0
    # 6-byte big-endian authority
    authority = int.from_bytes(data[offset + 2:offset + 8], 'big')
    subs = []
    pos = offset + 8
    for _ in range(sub_count):
        subs.append(struct.unpack_from('<I', data, pos)[0])
        pos += 4
    sid = f'S-{revision}-{authority}' + ''.join(f'-{s}' for s in subs)
    return sid, 8 + sub_count * 4


def _sid_to_sddl(sid_string, domain_sid=None):
    """Convert SID string to SDDL abbreviation if well-known, else return SID."""
    if sid_string in _WELLKNOWN_SIDS:
        return _WELLKNOWN_SIDS[sid_string]
    # Check domain-relative RIDs
    if domain_sid and sid_string.startswith(domain_sid + '-'):
        tail = sid_string[len(domain_sid) + 1:]
        try:
            rid = int(tail)
            if rid in _DOMAIN_RID_SDDL:
                return _DOMAIN_RID_SDDL[rid]
        except ValueError:
            pass
    return sid_string


def _ace_flags_to_sddl(flags):
    """Convert ACE flags byte to SDDL flag string."""
    parts = []
    if flags & 0x02: parts.append('CI')  # Container Inherit
    if flags & 0x01: parts.append('OI')  # Object Inherit
    if flags & 0x04: parts.append('NP')  # No Propagate Inherit
    if flags & 0x08: parts.append('IO')  # Inherit Only
    if flags & 0x10: parts.append('ID')  # Inherited
    if flags & 0x40: parts.append('SA')  # Successful Access
    if flags & 0x80: parts.append('FA')  # Failed Access
    return ''.join(parts)


def _access_mask_to_sddl(mask):
    """Convert access mask uint32 to SDDL rights string."""
    # Check generic rights first (full match)
    if mask == 0x10000000: return 'GA'  # Generic All
    if mask == 0x80000000: return 'GR'  # Generic Read
    if mask == 0x40000000: return 'GW'  # Generic Write
    if mask == 0x20000000: return 'GX'  # Generic Execute

    parts = []
    # Standard rights
    if mask & 0x10000000: parts.append('GA')
    if mask & 0x80000000: parts.append('GR')
    if mask & 0x40000000: parts.append('GW')
    if mask & 0x20000000: parts.append('GX')
    remaining = mask & ~0xF0000000

    # Map individual standard and DS-specific bits
    _RIGHTS = [
        (0x00010000, 'SD'),  # DELETE
        (0x00020000, 'RC'),  # READ_CONTROL
        (0x00040000, 'WD'),  # WRITE_DAC
        (0x00080000, 'WO'),  # WRITE_OWNER
        (0x00000001, 'CC'),  # CREATE_CHILD / DS
        (0x00000002, 'DC'),  # DELETE_CHILD / DS
        (0x00000004, 'LC'),  # LIST_CONTENTS / DS
        (0x00000008, 'SW'),  # SELF / DS WRITE SELF
        (0x00000010, 'RP'),  # READ_PROP / DS
        (0x00000020, 'WP'),  # WRITE_PROP / DS
        (0x00000040, 'DT'),  # DELETE_TREE / DS
        (0x00000080, 'LO'),  # LIST_OBJECT / DS
        (0x00000100, 'CR'),  # CONTROL_ACCESS / DS Extended Right
    ]
    for bit, abbr in _RIGHTS:
        if remaining & bit:
            parts.append(abbr)
            remaining &= ~bit
    if remaining:
        parts.append(f'0x{remaining:x}')
    return ''.join(parts)


def _guid_to_string(data, offset):
    """Parse 16-byte mixed-endian GUID at offset, return lowercase string."""
    if offset + 16 > len(data):
        return '00000000-0000-0000-0000-000000000000'
    # First 3 components are little-endian, last 2 are big-endian
    d1 = struct.unpack_from('<I', data, offset)[0]
    d2 = struct.unpack_from('<H', data, offset + 4)[0]
    d3 = struct.unpack_from('<H', data, offset + 6)[0]
    rest = data[offset + 8:offset + 16]
    return f'{d1:08x}-{d2:04x}-{d3:04x}-{rest[:2].hex()}-{rest[2:].hex()}'


def _acl_control_flags_to_sddl(control, is_dacl):
    """Convert SD control flags to SDDL ACL flags (P, AI, AR)."""
    parts = []
    if is_dacl:
        if control & 0x1000: parts.append('P')   # SE_DACL_PROTECTED
        if control & 0x0400: parts.append('AI')  # SE_DACL_AUTO_INHERITED
        if control & 0x0100: parts.append('AR')  # SE_DACL_AUTO_INHERIT_REQ
    else:
        if control & 0x2000: parts.append('P')   # SE_SACL_PROTECTED
        if control & 0x0800: parts.append('AI')  # SE_SACL_AUTO_INHERITED
        if control & 0x0200: parts.append('AR')  # SE_SACL_AUTO_INHERIT_REQ
    return ''.join(parts)


# ACE type names for SDDL
_ACE_TYPE_SDDL = {
    0x00: 'A',   # ACCESS_ALLOWED
    0x01: 'D',   # ACCESS_DENIED
    0x02: 'AU',  # SYSTEM_AUDIT
    0x05: 'OA',  # ACCESS_ALLOWED_OBJECT
    0x06: 'OD',  # ACCESS_DENIED_OBJECT
    0x07: 'OU',  # SYSTEM_AUDIT_OBJECT
    0x09: 'A',   # ACCESS_ALLOWED_CALLBACK (treat as A)
    0x0A: 'D',   # ACCESS_DENIED_CALLBACK
    0x0B: 'XA',  # ACCESS_ALLOWED_CALLBACK_OBJECT → XA
    0x0C: 'XD',  # ACCESS_DENIED_CALLBACK_OBJECT → XD
    0x11: 'XA',  # SYSTEM_MANDATORY_LABEL → treat as XA
}


def sd_to_sddl(data, domain_sid=None):
    """Convert binary SECURITY_DESCRIPTOR_RELATIVE to SDDL string.

    Args:
        data: bytes of the security descriptor
        domain_sid: optional domain SID string (e.g. 'S-1-5-21-x-y-z') for
                    abbreviating domain-relative SIDs (DA, EA, etc.)

    Returns:
        SDDL string or error string on parse failure.
    """
    if len(data) < 20:
        return f'[SD too short: {len(data)} bytes]'

    revision = data[0]
    # Byte 1 is Sbz1
    control = struct.unpack_from('<H', data, 2)[0]
    off_owner = struct.unpack_from('<I', data, 4)[0]
    off_group = struct.unpack_from('<I', data, 8)[0]
    off_sacl = struct.unpack_from('<I', data, 12)[0]
    off_dacl = struct.unpack_from('<I', data, 16)[0]

    parts = []

    # Owner
    if off_owner and off_owner < len(data):
        owner_sid, _ = _sid_to_string(data, off_owner)
        if owner_sid:
            parts.append(f'O:{_sid_to_sddl(owner_sid, domain_sid)}')

    # Group
    if off_group and off_group < len(data):
        group_sid, _ = _sid_to_string(data, off_group)
        if group_sid:
            parts.append(f'G:{_sid_to_sddl(group_sid, domain_sid)}')

    # DACL
    if control & 0x0004 and off_dacl and off_dacl < len(data):  # SE_DACL_PRESENT
        dacl_str = _parse_acl(data, off_dacl, control, True, domain_sid)
        parts.append(f'D:{dacl_str}')

    # SACL
    if control & 0x0010 and off_sacl and off_sacl < len(data):  # SE_SACL_PRESENT
        sacl_str = _parse_acl(data, off_sacl, control, False, domain_sid)
        parts.append(f'S:{sacl_str}')

    return ''.join(parts)


def _parse_acl(data, offset, control, is_dacl, domain_sid):
    """Parse an ACL at the given offset and return SDDL ACE string."""
    if offset + 8 > len(data):
        return '[acl-truncated]'

    flags_str = _acl_control_flags_to_sddl(control, is_dacl)
    # ACL header: revision(1), sbz1(1), size(2), ace_count(2), sbz2(2)
    acl_size = struct.unpack_from('<H', data, offset + 2)[0]
    ace_count = struct.unpack_from('<H', data, offset + 4)[0]

    aces = []
    ace_offset = offset + 8
    for _ in range(ace_count):
        if ace_offset + 4 > len(data):
            break
        ace_type = data[ace_offset]
        ace_flags = data[ace_offset + 1]
        ace_size = struct.unpack_from('<H', data, ace_offset + 2)[0]
        if ace_size < 4 or ace_offset + ace_size > len(data):
            break

        ace_str = _parse_ace(data, ace_offset, ace_type, ace_flags, ace_size, domain_sid)
        if ace_str:
            aces.append(ace_str)
        ace_offset += ace_size

    return flags_str + ''.join(aces)


def _parse_ace(data, offset, ace_type, ace_flags, ace_size, domain_sid):
    """Parse a single ACE and return SDDL string like (A;CI;RPWP;;;DA)."""
    type_str = _ACE_TYPE_SDDL.get(ace_type)
    if type_str is None:
        return f'(Unknown ACE type 0x{ace_type:02x})'

    flags_str = _ace_flags_to_sddl(ace_flags)

    # Body starts after 4-byte ACE header
    body = offset + 4

    if ace_type in (0x05, 0x06, 0x07, 0x0B, 0x0C):
        # Object ACE: mask(4) + obj_flags(4) + optional GUIDs + SID
        if body + 8 > offset + ace_size:
            return None
        mask = struct.unpack_from('<I', data, body)[0]
        obj_flags = struct.unpack_from('<I', data, body + 4)[0]
        guid_offset = body + 8
        object_guid = ''
        inherit_guid = ''
        if obj_flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
            object_guid = _guid_to_string(data, guid_offset)
            guid_offset += 16
        if obj_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
            inherit_guid = _guid_to_string(data, guid_offset)
            guid_offset += 16
        sid_str, _ = _sid_to_string(data, guid_offset)
        sid_sddl = _sid_to_sddl(sid_str, domain_sid) if sid_str else ''
        rights_str = _access_mask_to_sddl(mask)
        return f'({type_str};{flags_str};{rights_str};{object_guid};{inherit_guid};{sid_sddl})'
    else:
        # Basic ACE: mask(4) + SID
        if body + 4 > offset + ace_size:
            return None
        mask = struct.unpack_from('<I', data, body)[0]
        sid_str, _ = _sid_to_string(data, body + 4)
        sid_sddl = _sid_to_sddl(sid_str, domain_sid) if sid_str else ''
        rights_str = _access_mask_to_sddl(mask)
        return f'({type_str};{flags_str};{rights_str};;;{sid_sddl})'


def _auto_detect_domain_sid(b64_values):
    """Scan base64-encoded SDs to find the most common S-1-5-21-x-y-z prefix."""
    sid_prefixes = Counter()
    for b64 in b64_values[:50]:  # Sample first 50
        try:
            sd_data = base64.b64decode(b64)
        except Exception:
            continue
        if len(sd_data) < 20:
            continue
        off_owner = struct.unpack_from('<I', sd_data, 4)[0]
        if off_owner and off_owner + 8 < len(sd_data):
            sid_str, _ = _sid_to_string(sd_data, off_owner)
            if sid_str and sid_str.startswith('S-1-5-21-'):
                # Domain SID is everything except the last RID
                parts = sid_str.split('-')
                if len(parts) >= 5:
                    domain = '-'.join(parts[:7])  # S-1-5-21-x-y-z
                    sid_prefixes[domain] += 1
    if sid_prefixes:
        return sid_prefixes.most_common(1)[0][0]
    return None


def _inject_sddl_comments(xml_text):
    """Post-process XML text to inject SDDL comments after nTSecurityDescriptor values."""
    # Regex to find nTSecurityDescriptor elements with base64 content
    pattern = re.compile(
        r'(<[^>]*nTSecurityDescriptor[^>]*>'   # opening tag (possibly with namespace prefix)
        r'(?:<[^>]*>)*'                         # optional inner tags like <ad:value ...>
        r')([A-Za-z0-9+/=\s]+?)'               # base64 content (group 2)
        r'(</)',                                 # start of closing tag
        re.DOTALL
    )

    # First pass: collect all base64 values for domain SID detection
    b64_values = []
    for m in pattern.finditer(xml_text):
        b64 = m.group(2).strip()
        if len(b64) > 10:
            b64_values.append(b64)

    domain_sid = _auto_detect_domain_sid(b64_values)

    decoded_count = 0
    error_count = 0

    def _replace(m):
        nonlocal decoded_count, error_count
        prefix = m.group(1)
        b64 = m.group(2).strip()
        close = m.group(3)
        try:
            sd_data = base64.b64decode(b64)
            sddl = sd_to_sddl(sd_data, domain_sid)
            decoded_count += 1
            # Reconstruct: original content + closing, then SDDL comment on next line
            return f'{prefix}{m.group(2)}{close}'[:-len(close)] + \
                   f'{m.group(2)}{close}'
        except Exception as e:
            error_count += 1
            return m.group(0)

    # Actually do the replacement with comment injection
    def _replace_full(m):
        nonlocal decoded_count, error_count
        b64 = m.group(2).strip()
        try:
            sd_data = base64.b64decode(b64)
            sddl = sd_to_sddl(sd_data, domain_sid)
            decoded_count += 1
        except Exception as e:
            error_count += 1
            sddl = f'[SDDL decode error: {e}]'
        return m.group(0)  # Keep original match, we'll do line-based injection instead

    # Simpler approach: find complete nTSecurityDescriptor elements and append comment
    # Pattern: everything from <...nTSecurityDescriptor...> to </...nTSecurityDescriptor...>
    full_pattern = re.compile(
        r'(<[^>]*nTSecurityDescriptor[^>]*>.*?</[^>]*nTSecurityDescriptor[^>]*>)',
        re.DOTALL
    )

    def _inject_comment(m):
        nonlocal decoded_count, error_count
        element = m.group(1)
        # Extract base64 from inside
        b64_match = re.search(r'>([A-Za-z0-9+/=\s]{20,})<', element)
        if not b64_match:
            return element
        b64 = b64_match.group(1).strip()
        try:
            sd_data = base64.b64decode(b64)
            sddl = sd_to_sddl(sd_data, domain_sid)
            decoded_count += 1
            return f'{element}\n<!-- SDDL: {sddl} -->'
        except Exception as e:
            error_count += 1
            return f'{element}\n<!-- SDDL decode error: {e} -->'

    result = full_pattern.sub(_inject_comment, xml_text)

    if decoded_count or error_count:
        print(f"  SDDL: decoded {decoded_count} nTSecurityDescriptor values"
              f"{f', {error_count} errors' if error_count else ''}"
              f"{f', domain SID: {domain_sid}' if domain_sid else ''}")

    return result


# ─── NTLM Decryption Support ─────────────────────────────────────────────────

def password_to_nthash(password):
    """Derive NT hash from a plaintext password: MD4(UTF-16-LE(password))."""
    from Cryptodome.Hash import MD4
    return MD4.new(password.encode('utf-16-le')).digest()


def extract_ntlm_from_sasl(data, is_c2s):
    """Parse NMS preamble and SASL frames, extract NTLM Type 1/2/3 messages.

    Works for both raw-NTLM and SPNEGO-wrapped NTLM since we search for
    the NTLMSSP\\x00 signature regardless of wrapping.

    Returns dict with keys 'type1', 'type2', 'type3' mapping to message bytes.
    """
    result = {}
    marker = b'NTLMSSP\x00'
    pos = 0
    while True:
        idx = data.find(marker, pos)
        if idx < 0:
            break
        # Message type is a 4-byte LE uint32 right after the signature
        if idx + 12 > len(data):
            break
        msg_type = struct.unpack_from('<I', data, idx + 8)[0]

        # Determine message boundaries: scan for next NTLMSSP or use
        # a reasonable heuristic. For SASL frames the NTLM message is
        # embedded inside a framed structure, so we take until the next
        # marker or end of data, but cap at a reasonable size.
        next_idx = data.find(marker, idx + 12)
        if next_idx < 0:
            next_idx = len(data)
        msg_data = data[idx:next_idx]

        if msg_type == 1:
            result['type1'] = msg_data
        elif msg_type == 2:
            result['type2'] = msg_data
        elif msg_type == 3:
            result['type3'] = msg_data

        pos = idx + 12
    return result


def derive_ntlm_session_key(type2_msg, type3_msg, nt_hash):
    """Derive NTLM session keys from Type 2 (challenge) and Type 3 (authenticate).

    Returns (exported_session_key, client_sealing_key, server_sealing_key, principal).
    Raises ValueError if the NT hash doesn't match.
    """
    # Parse ServerChallenge from Type 2 (offset 24, 8 bytes)
    if len(type2_msg) < 32:
        raise ValueError("Type 2 message too short")
    server_challenge = type2_msg[24:32]

    # Parse Type 3 message fields
    if len(type3_msg) < 72:
        raise ValueError("Type 3 message too short")

    # NtChallengeResponse: security buffer at offset 20 (len:2, maxlen:2, offset:4)
    nt_resp_len = struct.unpack_from('<H', type3_msg, 20)[0]
    nt_resp_off = struct.unpack_from('<I', type3_msg, 24)[0]
    nt_response = type3_msg[nt_resp_off:nt_resp_off + nt_resp_len]

    # Domain: security buffer at offset 28
    domain_len = struct.unpack_from('<H', type3_msg, 28)[0]
    domain_off = struct.unpack_from('<I', type3_msg, 32)[0]
    domain = type3_msg[domain_off:domain_off + domain_len].decode('utf-16-le', errors='replace')

    # User: security buffer at offset 36
    user_len = struct.unpack_from('<H', type3_msg, 36)[0]
    user_off = struct.unpack_from('<I', type3_msg, 40)[0]
    user = type3_msg[user_off:user_off + user_len].decode('utf-16-le', errors='replace')

    # EncryptedRandomSessionKey: security buffer at offset 52
    enc_sess_key_len = struct.unpack_from('<H', type3_msg, 52)[0]
    enc_sess_key_off = struct.unpack_from('<I', type3_msg, 56)[0]
    encrypted_random_session_key = type3_msg[enc_sess_key_off:enc_sess_key_off + enc_sess_key_len]

    # NegotiateFlags at offset 60
    negotiate_flags = struct.unpack_from('<I', type3_msg, 60)[0]

    # NTProofStr is the first 16 bytes of NtChallengeResponse
    if len(nt_response) < 16:
        raise ValueError("NtChallengeResponse too short")
    nt_proof_str = nt_response[:16]
    # The rest is the NTv2 client blob
    client_blob = nt_response[16:]

    # ResponseKeyNT = HMAC_MD5(NT_Hash, UPPERCASE(User) + Domain) -- both UTF-16-LE
    response_key_nt = hmac.new(
        nt_hash,
        user.upper().encode('utf-16-le') + domain.encode('utf-16-le'),
        hashlib.md5
    ).digest()

    # Verify: NTProofStr should equal HMAC_MD5(ResponseKeyNT, ServerChallenge + ClientBlob)
    expected_proof = hmac.new(
        response_key_nt,
        server_challenge + client_blob,
        hashlib.md5
    ).digest()

    if nt_proof_str != expected_proof:
        raise ValueError("NT hash does not match (NTProofStr verification failed)")

    # SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
    session_base_key = hmac.new(response_key_nt, nt_proof_str, hashlib.md5).digest()

    # ExportedSessionKey: if KEY_EXCH flag (0x40000000) is set, decrypt it
    key_exch = negotiate_flags & 0x40000000
    if key_exch and encrypted_random_session_key:
        rc4 = ARC4.new(session_base_key)
        exported_session_key = rc4.decrypt(encrypted_random_session_key)
    else:
        exported_session_key = session_base_key

    # Derive sealing keys (MS-NLMP section 3.4.4)
    # ClientSealingKey = MD5(ExportedSessionKey + "session key to client-to-server sealing key magic constant\x00")
    client_sealing_key = hashlib.md5(
        exported_session_key +
        b'session key to client-to-server sealing key magic constant\x00'
    ).digest()

    server_sealing_key = hashlib.md5(
        exported_session_key +
        b'session key to server-to-client sealing key magic constant\x00'
    ).digest()

    principal = f'{domain}\\{user}'
    return exported_session_key, client_sealing_key, server_sealing_key, principal


def decrypt_ntlm_seal(frames, sealing_key):
    """Decrypt NTLM-sealed frames using RC4.

    Each frame has a 16-byte signature (Version:4 + Checksum:8 + SeqNum:4)
    followed by the encrypted message body.

    The RC4 cipher state persists across frames (streaming cipher).
    After decrypting each message, we also advance the RC4 state by
    decrypting the 8-byte checksum (for state synchronization).
    """
    rc4 = ARC4.new(sealing_key)
    plaintext_parts = []

    for frame in frames:
        if len(frame) < 16:
            continue
        # Signature: Version(4) + Checksum(8) + SeqNum(4)
        checksum = frame[4:12]
        message_ciphertext = frame[16:]

        if message_ciphertext:
            plaintext = rc4.decrypt(message_ciphertext)
            plaintext_parts.append(plaintext)

        # Advance RC4 state for checksum (keeps cipher in sync)
        rc4.decrypt(checksum)

    return b''.join(plaintext_parts)


def extract_ntlm_keys(c2s, s2c, nt_hashes):
    """Extract NTLM session keys from the TCP stream data.

    Parallel to extract_keys() for Kerberos.
    Returns (client_sealing_key, server_sealing_key, principal).
    """
    # Extract NTLM messages from both directions
    c2s_ntlm = extract_ntlm_from_sasl(c2s, True)
    s2c_ntlm = extract_ntlm_from_sasl(s2c, False)

    # Type 3 (Authenticate) comes from client, Type 2 (Challenge) from server
    type3 = c2s_ntlm.get('type3')
    type2 = s2c_ntlm.get('type2')

    if not type2:
        raise ValueError("NTLM Type 2 (Challenge) not found in server data")
    if not type3:
        raise ValueError("NTLM Type 3 (Authenticate) not found in client data")

    # Try each NT hash
    last_error = None
    for nt_hash in nt_hashes:
        try:
            _, client_seal, server_seal, principal = derive_ntlm_session_key(
                type2, type3, nt_hash)
            return client_seal, server_seal, principal
        except ValueError as e:
            last_error = e
            continue

    raise ValueError(f"No NT hash matched the NTLM exchange (last error: {last_error})")


# ─── Analyst Summary Report ──────────────────────────────────────────────────

import xml.etree.ElementTree as ET
from datetime import datetime

NS = {
    's': 'http://www.w3.org/2003/05/soap-envelope',
    'a': 'http://www.w3.org/2005/08/addressing',
    'wsen': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration',
    'ad': 'http://schemas.microsoft.com/2008/1/ActiveDirectory',
    'addata': 'http://schemas.microsoft.com/2008/1/ActiveDirectory/Data',
    'adlq': 'http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery',
}

UAC_FLAGS = {
    0x0001: 'SCRIPT',
    0x0002: 'ACCOUNTDISABLE',
    0x0008: 'HOMEDIR_REQUIRED',
    0x0010: 'LOCKOUT',
    0x0020: 'PASSWD_NOTREQD',
    0x0040: 'PASSWD_CANT_CHANGE',
    0x0080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
    0x0100: 'TEMP_DUPLICATE_ACCOUNT',
    0x0200: 'NORMAL_ACCOUNT',
    0x0800: 'INTERDOMAIN_TRUST_ACCOUNT',
    0x1000: 'WORKSTATION_TRUST_ACCOUNT',
    0x2000: 'SERVER_TRUST_ACCOUNT',
    0x10000: 'DONT_EXPIRE_PASSWORD',
    0x20000: 'MNS_LOGON_ACCOUNT',
    0x40000: 'SMARTCARD_REQUIRED',
    0x80000: 'TRUSTED_FOR_DELEGATION',
    0x100000: 'NOT_DELEGATED',
    0x200000: 'USE_DES_KEY_ONLY',
    0x400000: 'DONT_REQ_PREAUTH',
    0x800000: 'PASSWORD_EXPIRED',
    0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
    0x4000000: 'PARTIAL_SECRETS_ACCOUNT',
}


def _decode_uac_flags(uac_int):
    """Decode userAccountControl integer to comma-separated flag names."""
    flags = []
    for bit, name in sorted(UAC_FLAGS.items()):
        if uac_int & bit:
            flags.append(name)
    return ', '.join(flags) if flags else str(uac_int)


_COMMENT_RE = re.compile(
    r'<!--\s*Conn=(\d+)\s+Port=(\d+)\s+Dir=(\w+)\s+Msg=(\d+)\s+Principal=(.+?)\s*-->')


def _parse_comment_header(line):
    """Extract Conn, Port, Dir, Msg, Principal from comment header."""
    m = _COMMENT_RE.search(line)
    if not m:
        return None
    return {
        'conn': int(m.group(1)),
        'port': int(m.group(2)),
        'dir': m.group(3),
        'msg': int(m.group(4)),
        'principal': m.group(5),
    }


def _local_name(tag):
    """Strip namespace URI from an ElementTree tag."""
    if '}' in tag:
        return tag.split('}', 1)[1]
    return tag


def _extract_ad_object(elem):
    """Extract AD attributes from an addata element, return {attr_name: [values]}."""
    obj = {}
    obj['_type'] = _local_name(elem.tag)
    for child in elem:
        attr_name = _local_name(child.tag)
        if attr_name == 'objectReferenceProperty':
            continue
        values = []
        for val_elem in child:
            if _local_name(val_elem.tag) == 'value' and val_elem.text:
                values.append(val_elem.text)
        if not values and child.text:
            values = [child.text]
        if values:
            obj[attr_name] = values
    return obj


def _parse_soap_messages(all_xml):
    """Parse all XML entries into structured message dicts."""
    parsed = []
    for entry in all_xml:
        lines = entry.split('\n', 1)
        header = _parse_comment_header(lines[0])
        if not header:
            continue

        xml_text = lines[1] if len(lines) > 1 else ''
        msg = dict(header)
        msg['action'] = ''
        msg['filter'] = ''
        msg['base_dn'] = ''
        msg['scope'] = ''
        msg['requested_attrs'] = []
        msg['ad_objects'] = []
        msg['fault_text'] = ''

        # Fix unescaped ampersands from NBFX decoder (e.g. LDAP filters like (&(...)))
        fixed_xml = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#)', '&amp;', xml_text)
        try:
            root = ET.fromstring(fixed_xml)
        except ET.ParseError:
            parsed.append(msg)
            continue

        # Extract SOAP Action
        for elem in root.iter():
            if _local_name(elem.tag) == 'Action' and elem.text:
                # Get last path segment of the action URI
                action = elem.text.rsplit('/', 1)[-1]
                msg['action'] = action
                break

        # Extract LDAP query details (Enumerate requests)
        for elem in root.iter():
            ln = _local_name(elem.tag)
            if ln == 'Filter' and elem.text and not elem.text.startswith('http'):
                msg['filter'] = elem.text.strip()
            elif ln == 'LdapQuery':
                for child in elem:
                    cln = _local_name(child.tag)
                    if cln == 'Filter' and child.text:
                        msg['filter'] = child.text.strip()
                    elif cln == 'BaseObject' and child.text:
                        msg['base_dn'] = child.text.strip()
                    elif cln == 'Scope' and child.text:
                        msg['scope'] = child.text.strip()

        # Extract requested attributes (SelectionProperty)
        for elem in root.iter():
            if _local_name(elem.tag) == 'SelectionProperty' and elem.text:
                attr = elem.text.strip()
                # Strip namespace prefix (d: or addata:)
                if ':' in attr:
                    attr = attr.split(':', 1)[1]
                msg['requested_attrs'].append(attr)

        # Extract AD objects from PullResponse/GetResponse Items
        for elem in root.iter():
            ln = _local_name(elem.tag)
            if ln == 'Items':
                for child in elem:
                    obj = _extract_ad_object(child)
                    if obj:
                        msg['ad_objects'].append(obj)
            # Also handle GetResponse body (addata:top, addata:user, etc.)
            elif ln in ('top', 'user', 'computer', 'group', 'organizationalUnit',
                        'domainDNS', 'container', 'groupPolicyContainer'):
                parent_ln = _local_name(elem.tag)
                # Only if it's directly in the Body
                obj = _extract_ad_object(elem)
                if obj and len(obj) > 1:  # more than just _type
                    msg['ad_objects'].append(obj)

        # Extract fault text
        for elem in root.iter():
            if _local_name(elem.tag) == 'Text' and elem.text:
                msg['fault_text'] = elem.text.strip()
                break

        parsed.append(msg)
    return parsed


def _detect_attack_patterns(parsed_messages):
    """Detect known attack patterns. Returns list of (severity, name, description, conn, principal)."""
    detections = []
    seen = set()

    for msg in parsed_messages:
        conn = msg['conn']
        principal = msg['principal']
        filt = msg.get('filter', '')
        attrs = msg.get('requested_attrs', [])
        key_base = (conn, principal)

        # AS-REP Roasting
        if 'userAccountControl:1.2.840.113556.1.4.803:=4194304' in filt:
            key = ('asrep', conn)
            if key not in seen:
                seen.add(key)
                detections.append(('HIGH', 'AS-REP Roasting',
                    f'LDAP filter targets DONT_REQ_PREAUTH accounts',
                    conn, principal))

        # SOAPHound
        if filt and 'soaphound' in filt.lower():
            key = ('soaphound_filter', conn)
            if key not in seen:
                seen.add(key)
                detections.append(('HIGH', 'SOAPHound',
                    f'Filter contains "soaphound" marker string',
                    conn, principal))
        elif attrs:
            sensitive_bulk = {'nTSecurityDescriptor', 'member', 'servicePrincipalName'}
            attr_set = set(attrs)
            if sensitive_bulk.issubset(attr_set) and len(attrs) >= 15:
                key = ('soaphound_bulk', conn)
                if key not in seen:
                    seen.add(key)
                    detections.append(('HIGH', 'SOAPHound',
                        f'Bulk enumeration with {len(attrs)} attrs including nTSecurityDescriptor + member + SPN',
                        conn, principal))

        # Kerberoasting Recon
        if filt and 'servicePrincipalName' in filt.lower():
            key = ('kerberoast', conn)
            if key not in seen:
                seen.add(key)
                detections.append(('MEDIUM', 'Kerberoasting Recon',
                    f'LDAP filter targets servicePrincipalName',
                    conn, principal))

        # Sensitive Attribute Harvesting
        sensitive_attrs = {'msDS-AllowedToDelegateTo', 'userPassword', 'unixUserPassword'}
        found_sensitive = sensitive_attrs.intersection(set(attrs))
        if found_sensitive:
            key = ('sensitive', conn)
            if key not in seen:
                seen.add(key)
                detections.append(('MEDIUM', 'Sensitive Attribute Harvesting',
                    f'Requesting: {", ".join(sorted(found_sensitive))}',
                    conn, principal))

    # Bulk AD Enumeration (check after all messages parsed)
    conn_objects = defaultdict(int)
    for msg in parsed_messages:
        conn_objects[msg['conn']] += len(msg.get('ad_objects', []))
    for msg in parsed_messages:
        conn = msg['conn']
        if conn_objects[conn] >= 20 and msg['action'] in ('Enumerate', 'Pull'):
            key = ('bulk', conn)
            if key not in seen:
                seen.add(key)
                detections.append(('INFO', 'Bulk AD Enumeration',
                    f'{conn_objects[conn]} objects returned in this connection',
                    conn, msg['principal']))

    return sorted(detections, key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}[x[0]])


def _truncate(s, maxlen):
    """Truncate string with ellipsis if needed."""
    if len(s) <= maxlen:
        return s
    return s[:maxlen - 3] + '...'


def _format_connection_table(parsed_messages):
    """Format connection summary as fixed-width table."""
    # Gather per-connection info
    conns = {}
    for msg in parsed_messages:
        c = msg['conn']
        if c not in conns:
            conns[c] = {
                'port': msg['port'],
                'principal': msg['principal'],
                'msgs': 0,
                'actions': set(),
            }
        conns[c]['msgs'] += 1
        if msg['action']:
            conns[c]['actions'].add(msg['action'])

    lines = []
    lines.append(f"  {'Conn':<6}{'Port':<8}{'Auth':<10}{'Principal':<35}{'Msgs':<6}{'Actions'}")
    lines.append(f"  {'─'*6}{'─'*8}{'─'*10}{'─'*35}{'─'*6}{'─'*50}")

    for c in sorted(conns.keys()):
        info = conns[c]
        p = info['principal']
        if '\\' in p:
            auth = 'NTLM'
        elif '@' in p:
            auth = 'Kerberos'
        else:
            auth = 'Unknown'
        actions = ', '.join(sorted(info['actions']))
        lines.append(f"  {c:<6}{info['port']:<8}{auth:<10}{p:<35}{info['msgs']:<6}{actions}")

    return '\n'.join(lines)


def _format_query_details(parsed_messages):
    """Format query details for Enumerate requests."""
    lines = []
    # Count response objects per connection
    conn_objects = defaultdict(int)
    for msg in parsed_messages:
        conn_objects[msg['conn']] += len(msg.get('ad_objects', []))

    for msg in parsed_messages:
        if msg['action'] != 'Enumerate' or not msg['filter']:
            continue
        lines.append(f"  Conn {msg['conn']} (Port {msg['port']}) - {msg['principal']}")
        lines.append(f"    Filter:     {_truncate(msg['filter'], 100)}")
        if msg['base_dn']:
            lines.append(f"    Base DN:    {msg['base_dn']}")
        if msg['scope']:
            lines.append(f"    Scope:      {msg['scope']}")
        if msg['requested_attrs']:
            lines.append(f"    Attributes: {len(msg['requested_attrs'])} requested")
            # Show first few
            shown = msg['requested_attrs'][:8]
            rest = len(msg['requested_attrs']) - len(shown)
            lines.append(f"                {', '.join(shown)}")
            if rest > 0:
                lines.append(f"                ... and {rest} more")
        if conn_objects[msg['conn']] > 0:
            lines.append(f"    Response:   {conn_objects[msg['conn']]} objects returned")
        lines.append('')

    return '\n'.join(lines)


def _dedup_objects(objects, key_attr='sAMAccountName'):
    """Deduplicate AD objects by key attribute, merging group memberships."""
    seen = {}
    for obj in objects:
        key_vals = obj.get(key_attr, [])
        key = key_vals[0] if key_vals else None
        if not key:
            # Fall back to distinguishedName
            dn_vals = obj.get('distinguishedName', [])
            key = dn_vals[0] if dn_vals else id(obj)
        if key in seen:
            # Merge: prefer non-empty values, union memberOf
            existing = seen[key]
            for attr, vals in obj.items():
                if attr == '_type':
                    continue
                if attr == 'memberOf':
                    existing_members = set(existing.get('memberOf', []))
                    existing_members.update(vals)
                    existing['memberOf'] = sorted(existing_members)
                elif attr not in existing or not existing[attr]:
                    existing[attr] = vals
                elif attr == 'adminCount' and vals and vals[0] == '1':
                    existing[attr] = vals
        else:
            seen[key] = dict(obj)
    return list(seen.values())


def _format_object_tables(parsed_messages):
    """Format extracted AD objects grouped by type, deduplicated."""
    users_raw = []
    computers_raw = []
    groups_raw = []
    other_types = Counter()

    for msg in parsed_messages:
        for obj in msg.get('ad_objects', []):
            otype = obj.get('_type', 'unknown')
            if otype == 'user':
                users_raw.append(obj)
            elif otype == 'computer':
                computers_raw.append(obj)
            elif otype == 'group':
                groups_raw.append(obj)
            elif otype not in ('top', 'domainDNS'):
                other_types[otype] += 1

    # Deduplicate
    users = _dedup_objects(users_raw, 'sAMAccountName')
    computers = _dedup_objects(computers_raw, 'sAMAccountName')
    groups = _dedup_objects(groups_raw, 'sAMAccountName')

    lines = []

    # Users table
    if users:
        lines.append(f"  Users ({len(users)} unique):")
        lines.append(f"    {'sAMAccountName':<22}{'DN (CN)':<28}{'admin':<7}{'UAC Flags':<70}{'SPNs':<6}{'Groups'}")
        lines.append(f"    {'─'*22}{'─'*28}{'─'*7}{'─'*70}{'─'*6}{'─'*30}")
        for u in users:
            sam = (u.get('sAMAccountName', [''])[0])
            dn = u.get('distinguishedName', [''])[0]
            cn = ''
            if dn.startswith('CN='):
                cn = dn.split(',', 1)[0][3:]
            admin = u.get('adminCount', [''])[0]
            uac_str = ''
            if 'userAccountControl' in u:
                try:
                    uac_int = int(u['userAccountControl'][0])
                    uac_str = _decode_uac_flags(uac_int)
                except ValueError:
                    uac_str = u['userAccountControl'][0]
            spns = len(u.get('servicePrincipalName', []))
            groups_list = u.get('memberOf', [])
            group_names = []
            for g in groups_list:
                if g.startswith('CN='):
                    group_names.append(g.split(',', 1)[0][3:])
            group_str = ', '.join(group_names)

            lines.append(f"    {sam:<22}{_truncate(cn, 26):<28}{admin:<7}{uac_str:<70}{spns:<6}{group_str}")
        lines.append('')

    # Computers table
    if computers:
        lines.append(f"  Computers ({len(computers)} unique):")
        lines.append(f"    {'Name':<22}{'dNSHostName':<40}{'OS'}")
        lines.append(f"    {'─'*22}{'─'*40}{'─'*40}")
        for c in computers:
            name = c.get('name', c.get('sAMAccountName', ['']))[0] if c.get('name', c.get('sAMAccountName')) else ''
            dns = c.get('dNSHostName', [''])[0]
            os_val = c.get('operatingSystem', [''])[0]
            lines.append(f"    {name:<22}{dns:<40}{os_val}")
        lines.append('')

    # Groups table
    if groups:
        lines.append(f"  Groups ({len(groups)} unique):")
        lines.append(f"    {'Name':<45}{'Members'}")
        lines.append(f"    {'─'*45}{'─'*10}")
        for g in groups:
            name = g.get('name', g.get('sAMAccountName', ['']))[0] if g.get('name', g.get('sAMAccountName')) else ''
            members = len(g.get('member', []))
            lines.append(f"    {name:<45}{members}")
        lines.append('')

    # Other types
    if other_types:
        lines.append(f"  Other object types:")
        for otype, count in other_types.most_common():
            lines.append(f"    {otype}: {count}")
        lines.append('')

    if not lines:
        lines.append('  No AD objects extracted.')

    return '\n'.join(lines)


def _format_statistics(parsed_messages):
    """Format summary statistics."""
    conns = set()
    principals = set()
    obj_types = Counter()
    faults = 0

    for msg in parsed_messages:
        conns.add(msg['conn'])
        principals.add(msg['principal'])
        if msg['fault_text']:
            faults += 1
        for obj in msg.get('ad_objects', []):
            obj_types[obj.get('_type', 'unknown')] += 1

    lines = []
    lines.append(f"  Total SOAP messages: {len(parsed_messages)}")
    lines.append(f"  Connections:         {len(conns)}")
    lines.append(f"  Unique principals:   {len(principals)}")
    if principals:
        for p in sorted(principals):
            lines.append(f"    - {p}")
    lines.append(f"  SOAP faults:         {faults}")
    total_obj = sum(obj_types.values())
    lines.append(f"  AD objects:          {total_obj}")
    for otype, count in obj_types.most_common():
        lines.append(f"    - {otype}: {count}")
    return '\n'.join(lines)


def generate_summary_report(all_xml, pcap_path):
    """Generate analyst summary report from parsed SOAP messages."""
    parsed = _parse_soap_messages(all_xml)
    detections = _detect_attack_patterns(parsed)
    pcap_name = os.path.basename(pcap_path)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    sections = []

    # Header
    sections.append('=' * 78)
    sections.append('ADWS Decryption - Analyst Summary Report')
    sections.append('=' * 78)
    sections.append(f'Pcap:      {pcap_name}')
    sections.append(f'Generated: {timestamp}')
    sections.append('')

    # Connection Summary
    sections.append('─' * 78)
    sections.append('CONNECTION SUMMARY')
    sections.append('─' * 78)
    sections.append(_format_connection_table(parsed))
    sections.append('')

    # Attack Pattern Detection
    sections.append('─' * 78)
    sections.append('ATTACK PATTERN DETECTION')
    sections.append('─' * 78)
    if detections:
        for severity, name, desc, conn, principal in detections:
            if severity == 'HIGH':
                marker = '[!]'
            elif severity == 'MEDIUM':
                marker = '[*]'
            else:
                marker = '[i]'
            sections.append(f'  {marker} {severity}: {name} (Conn {conn}, {principal})')
            sections.append(f'      {desc}')
    else:
        sections.append('  No known attack patterns detected.')
    sections.append('')

    # Query Details
    sections.append('─' * 78)
    sections.append('QUERY DETAILS')
    sections.append('─' * 78)
    qd = _format_query_details(parsed)
    if qd.strip():
        sections.append(qd)
    else:
        sections.append('  No enumeration queries found.')
    sections.append('')

    # Extracted Objects
    sections.append('─' * 78)
    sections.append('EXTRACTED AD OBJECTS')
    sections.append('─' * 78)
    sections.append(_format_object_tables(parsed))

    # Statistics
    sections.append('─' * 78)
    sections.append('STATISTICS')
    sections.append('─' * 78)
    sections.append(_format_statistics(parsed))
    sections.append('')
    sections.append('=' * 78)

    return '\n'.join(sections)


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Decrypt ADWS NMS (.NET Message Security) traffic from pcap/pcapng')
    parser.add_argument('pcap',
        help='Path to pcap or pcapng file')
    parser.add_argument('keytab', nargs='?', default=None,
        help='Path to MIT keytab v2 file (required for Kerberos decryption)')
    parser.add_argument('--port', type=int, default=0,
        help='ADWS port (default: auto-detect, or 9389)')
    parser.add_argument('--nthash', action='append', default=[],
        help='NT hash as hex string (can be specified multiple times)')
    parser.add_argument('--password', action='append', default=[],
        help='Password to derive NT hash from (can be specified multiple times)')
    args = parser.parse_args()

    pcap_path = args.pcap
    keytab_path = args.keytab
    target_port = args.port

    # Build list of NT hashes
    nt_hashes = []
    for h in args.nthash:
        nt_hashes.append(bytes.fromhex(h))
    for pw in args.password:
        nt_hashes.append(password_to_nthash(pw))

    if not keytab_path and not nt_hashes:
        parser.error('At least one of keytab or --nthash/--password is required')

    print(f"Pcap: {pcap_path}")
    if keytab_path:
        print(f"Keytab: {keytab_path}")
    if nt_hashes:
        print(f"NT hashes: {len(nt_hashes)} provided")

    # Parse keytab
    keytab_entries = []
    if keytab_path:
        print(f"\nParsing keytab...")
        keytab_entries = parse_keytab(keytab_path)

    # Open pcap
    print(f"\nOpening capture file...")
    reader = open_pcap(pcap_path)

    # First pass: extract all TCP packets
    print(f"\nExtracting packets...")
    all_packets = []  # (src_ip, dst_ip, sp, dp, seq, payload)
    ipv4_count = 0
    ipv6_count = 0

    for ts, buf in reader:
        try:
            eth = dpkt.ethernet.Ethernet(buf)

            if eth.type == 0x0800:  # IPv4
                result = extract_tcp_from_ipv4(bytes(eth.data))
                if result and result[5]:
                    all_packets.append(result)
                    ipv4_count += 1

            elif eth.type == 0x86DD:  # IPv6
                result = extract_tcp_from_ipv6(bytes(eth.data))
                if result and result[5]:
                    all_packets.append(result)
                    ipv6_count += 1

        except Exception:
            pass

    print(f"  IPv4 TCP packets with data: {ipv4_count}")
    print(f"  IPv6 TCP packets with data: {ipv6_count}")
    print(f"  Total: {len(all_packets)}")

    # Port detection
    if target_port == 0:
        detected = detect_adws_ports(all_packets)
        if detected:
            target_port = min(detected)  # Pick the lowest if multiple
            print(f"\n  Auto-detected ADWS port: {target_port}")
        else:
            target_port = 9389
            print(f"\n  No NMF preamble found, using default port: {target_port}")
    else:
        print(f"\n  Using specified port: {target_port}")

    # Build connections with TCP reassembly
    # Connection key: (client_ip_hex, client_port)
    connections = defaultdict(lambda: {'C2S': TCPReassembler(), 'S2C': TCPReassembler()})

    for src_ip, dst_ip, sp, dp, seq, payload in all_packets:
        src_hex = src_ip.hex() if isinstance(src_ip, bytes) else src_ip.hex() if hasattr(src_ip, 'hex') else src_ip
        dst_hex = dst_ip.hex() if isinstance(dst_ip, bytes) else dst_ip.hex() if hasattr(dst_ip, 'hex') else dst_ip

        if dp == target_port:
            connections[(src_hex, sp)]['C2S'].add(seq, payload)
        elif sp == target_port:
            connections[(dst_hex, dp)]['S2C'].add(seq, payload)

    print(f"\n  TCP connections to port {target_port}: {len(connections)}")

    all_xml = []
    all_raw = []

    for ci, (ck, dirs) in enumerate(connections.items()):
        _, src_port = ck
        c2s, c2s_gaps = dirs['C2S'].reassemble()
        s2c, s2c_gaps = dirs['S2C'].reassemble()
        if not c2s or not s2c:
            continue

        print(f"\n{'='*70}")
        print(f"Connection {ci+1}: client port {src_port}")
        print(f"  C2S: {len(c2s)} bytes ({c2s_gaps} gaps)")
        print(f"  S2C: {len(s2c)} bytes ({s2c_gaps} gaps)")
        if c2s_gaps or s2c_gaps:
            print(f"  WARNING: TCP gaps detected — decryption may fail")

        auth_method = None
        principal = None
        client_seal_key = None
        server_seal_key = None
        ssk = None

        # Try Kerberos first
        if keytab_entries:
            try:
                sk, csk, ssk, principal = extract_keys(c2s, s2c, keytab_entries)
                auth_method = 'kerberos'
                print(f"  Auth: Kerberos | Principal: {principal}")
            except Exception as e:
                kerb_err = str(e)
                if 'AP-REQ not found' not in kerb_err and 'AP-REP not found' not in kerb_err:
                    print(f"  Kerberos failed: {kerb_err}")

        # Try NTLM if Kerberos didn't work
        if auth_method is None and nt_hashes:
            try:
                client_seal_key, server_seal_key, principal = extract_ntlm_keys(
                    c2s, s2c, nt_hashes)
                auth_method = 'ntlm'
                print(f"  Auth: NTLM | Principal: {principal}")
            except Exception as e:
                ntlm_err = str(e)
                if 'not found' not in ntlm_err:
                    print(f"  NTLM failed: {ntlm_err}")

        if auth_method is None:
            print(f"  Skipping (no supported auth found)")
            continue

        try:
            for direction, data, is_c2s, is_acc in [
                ('C2S', c2s, True, False), ('S2C', s2c, False, True)
            ]:
                frames = parse_ns_frames(data, is_c2s)
                dec_stream = b''

                if auth_method == 'kerberos':
                    for f in frames:
                        try:
                            pt = decrypt_gss_wrap_cfx(f, ssk, is_acc)
                            if pt: dec_stream += pt
                        except: pass
                elif auth_method == 'ntlm':
                    seal_key = client_seal_key if is_c2s else server_seal_key
                    dec_stream = decrypt_ntlm_seal(frames, seal_key)

                if not dec_stream: continue

                safe_principal = principal.replace('\\', '_').replace('/', '_')
                all_raw.append((
                    f'conn{ci+1}_port{src_port}_{direction}_{safe_principal}',
                    dec_stream))

                session_dict = {}
                messages = parse_nmf_records(dec_stream, session_dict)

                for mi, xml in enumerate(messages):
                    all_xml.append(
                        f'<!-- Conn={ci+1} Port={src_port} Dir={direction} '
                        f'Msg={mi} Principal={principal} -->\n{xml}')

                    print(f"\n  --- {direction} Message {mi} ---")
                    print(f"  {xml[:2000]}")
                    if len(xml) > 2000:
                        print(f"  ... ({len(xml)} chars total)")

        except Exception as e:
            print(f"  ERROR: {e}")
            import traceback; traceback.print_exc()

    base_dir = os.path.dirname(os.path.abspath(pcap_path))

    # Write decoded XML with SDDL annotations
    out_xml = os.path.join(base_dir, 'decrypted_adws.xml')
    combined_xml = '\n\n'.join(all_xml)
    print(f"\nPost-processing nTSecurityDescriptor values...")
    combined_xml = _inject_sddl_comments(combined_xml)
    with open(out_xml, 'w', encoding='utf-8') as f:
        f.write(combined_xml)

    # Write raw decrypted binary streams
    out_bin = os.path.join(base_dir, 'decrypted_adws_raw.bin')
    with open(out_bin, 'wb') as f:
        for label, raw_bytes in all_raw:
            label_enc = label.encode('utf-8')
            f.write(b'ADWS')
            f.write(struct.pack('<I', len(label_enc)))
            f.write(label_enc)
            f.write(struct.pack('<I', len(raw_bytes)))
            f.write(raw_bytes)

    # Also write per-stream files
    raw_dir = os.path.join(base_dir, 'decrypted_raw')
    os.makedirs(raw_dir, exist_ok=True)
    for label, raw_bytes in all_raw:
        stream_path = os.path.join(raw_dir, f'{label}.bin')
        with open(stream_path, 'wb') as f:
            f.write(raw_bytes)

    # Generate analyst summary report
    out_summary = os.path.join(base_dir, 'decrypted_adws_summary.txt')
    summary = generate_summary_report(all_xml, pcap_path)
    with open(out_summary, 'w', encoding='utf-8') as f:
        f.write(summary)

    print(f"\n{'='*70}")
    print(f"Wrote {len(all_xml)} decoded SOAP messages to {out_xml}")
    print(f"Wrote {len(all_raw)} raw decrypted streams to {out_bin}")
    print(f"Wrote {len(all_raw)} individual stream files to {raw_dir}/")
    print(f"Wrote analyst summary report to {out_summary}")


if __name__ == '__main__':
    main()
