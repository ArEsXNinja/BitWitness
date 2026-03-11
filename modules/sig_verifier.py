#!/usr/bin/env python3
"""
sig_verifier.py — Authenticode digital signature verification.
Uses Windows API (wintrust.dll, crypt32.dll) via ctypes to verify
Authenticode signatures on PE files and extract signer info.

No external dependencies required — uses only Python standard library.
"""

import os
import sys
import ctypes
import ctypes.wintypes

# ══════════════════════════════════════════════════════════════
#  PLATFORM CHECK
# ══════════════════════════════════════════════════════════════

SIG_VERIFIER_AVAILABLE = sys.platform == "win32"


# ══════════════════════════════════════════════════════════════
#  WINDOWS API CONSTANTS & STRUCTURES
# ══════════════════════════════════════════════════════════════

if SIG_VERIFIER_AVAILABLE:
    # WinVerifyTrust action GUID for Authenticode
    WINTRUST_ACTION_GENERIC_VERIFY_V2 = (
        ctypes.c_byte * 16
    )(
        0xAC, 0xC3, 0x11, 0x00,
        0x86, 0xB3,
        0xCF, 0x11,
        0xB5, 0x6F,
        0x00, 0xAA, 0x00, 0xBD, 0xF4, 0x23,
    )

    # WinTrust UI choices
    WTD_UI_NONE = 2

    # Revision/choice constants
    WTD_REVOKE_NONE = 0
    WTD_CHOICE_FILE = 1
    WTD_STATEACTION_VERIFY = 1
    WTD_STATEACTION_CLOSE = 2

    # Trust provider flags
    WTD_SAFER_FLAG = 0x100
    WTD_REVOCATION_CHECK_NONE = 0x10

    # Error codes
    TRUST_E_NOSIGNATURE = 0x800B0100
    TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
    TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
    TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
    TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
    CRYPT_E_SECURITY_SETTINGS = 0x80092026
    ERROR_SUCCESS = 0

    # Certificate store / query constants
    CERT_QUERY_OBJECT_FILE = 0x1
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400
    CERT_QUERY_FORMAT_FLAG_BINARY = 0x2

    CMSG_SIGNER_INFO_PARAM = 6
    CERT_INFO_ISSUER_FLAG = 4

    X509_ASN_ENCODING = 0x1
    PKCS_7_ASN_ENCODING = 0x10000

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct",       ctypes.wintypes.DWORD),
            ("pcwszFilePath",  ctypes.wintypes.LPCWSTR),
            ("hFile",          ctypes.wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct",            ctypes.wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData",      ctypes.c_void_p),
            ("dwUIChoice",          ctypes.wintypes.DWORD),
            ("fdwRevocationChecks", ctypes.wintypes.DWORD),
            ("dwUnionChoice",       ctypes.wintypes.DWORD),
            ("pFile",               ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction",       ctypes.wintypes.DWORD),
            ("hWVTStateData",       ctypes.wintypes.HANDLE),
            ("pwszURLReference",    ctypes.wintypes.LPCWSTR),
            ("dwProvFlags",         ctypes.wintypes.DWORD),
            ("dwUIContext",         ctypes.wintypes.DWORD),
        ]

    # Load DLLs
    try:
        _wintrust = ctypes.windll.wintrust
        _WinVerifyTrust = _wintrust.WinVerifyTrust
        _WinVerifyTrust.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        _WinVerifyTrust.restype = ctypes.c_long
        WINTRUST_LOADED = True
    except Exception:
        WINTRUST_LOADED = False

    try:
        _crypt32 = ctypes.windll.crypt32

        _CryptQueryObject = _crypt32.CryptQueryObject
        _CryptQueryObject.argtypes = [
            ctypes.wintypes.DWORD,   # dwObjectType
            ctypes.c_void_p,         # pvObject
            ctypes.wintypes.DWORD,   # dwExpectedContentTypeFlags
            ctypes.wintypes.DWORD,   # dwExpectedFormatTypeFlags
            ctypes.wintypes.DWORD,   # dwFlags
            ctypes.POINTER(ctypes.wintypes.DWORD),   # pdwMsgAndCertEncodingType
            ctypes.POINTER(ctypes.wintypes.DWORD),   # pdwContentType
            ctypes.POINTER(ctypes.wintypes.DWORD),   # pdwFormatType
            ctypes.POINTER(ctypes.c_void_p),         # phCertStore
            ctypes.POINTER(ctypes.c_void_p),         # phMsg
            ctypes.POINTER(ctypes.c_void_p),         # ppvContext
        ]
        _CryptQueryObject.restype = ctypes.wintypes.BOOL

        _CryptMsgGetParam = _crypt32.CryptMsgGetParam
        _CryptMsgGetParam.argtypes = [
            ctypes.c_void_p,         # hCryptMsg
            ctypes.wintypes.DWORD,   # dwParamType
            ctypes.wintypes.DWORD,   # dwIndex
            ctypes.c_void_p,         # pvData
            ctypes.POINTER(ctypes.wintypes.DWORD),  # pcbData
        ]
        _CryptMsgGetParam.restype = ctypes.wintypes.BOOL

        _CertFindCertificateInStore = _crypt32.CertFindCertificateInStore
        _CertFindCertificateInStore.argtypes = [
            ctypes.c_void_p,         # hCertStore
            ctypes.wintypes.DWORD,   # dwCertEncodingType
            ctypes.wintypes.DWORD,   # dwFindFlags
            ctypes.wintypes.DWORD,   # dwFindType
            ctypes.c_void_p,         # pvFindPara
            ctypes.c_void_p,         # pPrevCertContext
        ]
        _CertFindCertificateInStore.restype = ctypes.c_void_p

        _CertGetNameStringW = _crypt32.CertGetNameStringW
        _CertGetNameStringW.argtypes = [
            ctypes.c_void_p,         # pCertContext
            ctypes.wintypes.DWORD,   # dwType
            ctypes.wintypes.DWORD,   # dwFlags
            ctypes.c_void_p,         # pvTypePara
            ctypes.wintypes.LPWSTR,  # pszNameString
            ctypes.wintypes.DWORD,   # cchNameString
        ]
        _CertGetNameStringW.restype = ctypes.wintypes.DWORD

        _CertFreeCertificateContext = _crypt32.CertFreeCertificateContext
        _CertCloseStore = _crypt32.CertCloseStore
        _CryptMsgClose = _crypt32.CryptMsgClose

        CRYPT32_LOADED = True
    except Exception:
        CRYPT32_LOADED = False


# ══════════════════════════════════════════════════════════════
#  CERT_NAME_TYPE constants
# ══════════════════════════════════════════════════════════════

CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_ISSUER_FLAG_VAL = 0x1


# ══════════════════════════════════════════════════════════════
#  CORE VERIFICATION FUNCTIONS
# ══════════════════════════════════════════════════════════════

def verify_signature(file_path):
    """
    Verify the Authenticode digital signature of a file.

    Args:
        file_path: Path to the file (usually a PE executable).

    Returns:
        dict with keys:
            signed:      bool — True if the file has a valid signature
            status:      string — "valid", "invalid", "unsigned", "error"
            detail:      human-readable detail string
            signer:      signer name (if available)
            issuer:      certificate issuer (if available)
            error:       error string if something went wrong
    """
    if not SIG_VERIFIER_AVAILABLE:
        return {"error": "Signature verification is only available on Windows."}

    if not WINTRUST_LOADED:
        return {"error": "wintrust.dll could not be loaded."}

    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    abs_path = os.path.abspath(file_path)

    # Step 1: Verify with WinVerifyTrust
    trust_result = _winverifytrust(abs_path)

    # Step 2: Extract signer info if signed
    signer_info = {"signer": "N/A", "issuer": "N/A"}
    if trust_result["signed"]:
        try:
            signer_info = _get_signer_info(abs_path)
        except Exception:
            pass

    trust_result.update(signer_info)
    return trust_result


def verify_multiple(file_paths):
    """
    Verify signatures on multiple files.

    Args:
        file_paths: list of file paths

    Returns:
        dict with summary and per-file results.
    """
    results = []
    signed_count = 0
    unsigned_count = 0
    invalid_count = 0

    for fpath in file_paths:
        result = verify_signature(fpath)
        result["file"] = fpath
        results.append(result)

        if result.get("status") == "valid":
            signed_count += 1
        elif result.get("status") == "unsigned":
            unsigned_count += 1
        else:
            invalid_count += 1

    return {
        "results":        results,
        "total":          len(results),
        "signed_count":   signed_count,
        "unsigned_count": unsigned_count,
        "invalid_count":  invalid_count,
    }


# ══════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════

def _winverifytrust(file_path):
    """Call WinVerifyTrust to check Authenticode signature."""
    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = file_path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    trust_data.dwUnionChoice = WTD_CHOICE_FILE
    trust_data.pFile = ctypes.pointer(file_info)
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    trust_data.hWVTStateData = None
    trust_data.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE

    # Create a mutable copy of the GUID
    action_guid = (ctypes.c_byte * 16)()
    ctypes.memmove(action_guid, WINTRUST_ACTION_GENERIC_VERIFY_V2, 16)

    result = _WinVerifyTrust(
        None,
        ctypes.byref(action_guid),
        ctypes.byref(trust_data),
    )

    # Clean up
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    _WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(trust_data))

    # Interpret result
    # Convert to unsigned for comparison
    result_unsigned = result & 0xFFFFFFFF

    if result_unsigned == ERROR_SUCCESS:
        return {
            "signed": True,
            "status": "valid",
            "detail": "File has a valid Authenticode digital signature.",
        }
    elif result_unsigned == TRUST_E_NOSIGNATURE:
        return {
            "signed": False,
            "status": "unsigned",
            "detail": "File is NOT digitally signed.",
        }
    elif result_unsigned == TRUST_E_SUBJECT_NOT_TRUSTED:
        return {
            "signed": True,
            "status": "untrusted",
            "detail": "File is signed but the signature is NOT trusted.",
        }
    elif result_unsigned == TRUST_E_EXPLICIT_DISTRUST:
        return {
            "signed": True,
            "status": "distrusted",
            "detail": "File signature is explicitly distrusted.",
        }
    elif result_unsigned == TRUST_E_SUBJECT_FORM_UNKNOWN:
        return {
            "signed": False,
            "status": "unknown_format",
            "detail": "File format is not recognized for signature verification.",
        }
    elif result_unsigned == CRYPT_E_SECURITY_SETTINGS:
        return {
            "signed": False,
            "status": "blocked",
            "detail": "Security settings prevent verification.",
        }
    else:
        return {
            "signed": False,
            "status": "invalid",
            "detail": f"Signature verification failed (error: 0x{result_unsigned:08X}).",
        }


def _get_signer_info(file_path):
    """Extract signer and issuer from the file's embedded certificate."""
    if not CRYPT32_LOADED:
        return {"signer": "N/A (crypt32 unavailable)", "issuer": "N/A"}

    encoding = ctypes.wintypes.DWORD(0)
    content_type = ctypes.wintypes.DWORD(0)
    format_type = ctypes.wintypes.DWORD(0)
    cert_store = ctypes.c_void_p(0)
    crypt_msg = ctypes.c_void_p(0)
    context = ctypes.c_void_p(0)

    # Query the embedded PKCS#7 signed data
    file_path_ptr = ctypes.c_wchar_p(file_path)

    success = _CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        file_path_ptr,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        ctypes.byref(encoding),
        ctypes.byref(content_type),
        ctypes.byref(format_type),
        ctypes.byref(cert_store),
        ctypes.byref(crypt_msg),
        ctypes.byref(context),
    )

    if not success:
        return {"signer": "N/A", "issuer": "N/A"}

    try:
        # Get signer info size
        signer_size = ctypes.wintypes.DWORD(0)
        _CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(signer_size))

        if signer_size.value == 0:
            return {"signer": "N/A", "issuer": "N/A"}

        # Get signer info
        signer_buf = (ctypes.c_byte * signer_size.value)()
        _CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, ctypes.byref(signer_buf), ctypes.byref(signer_size))

        # Find the cert in the store
        cert_context = _CertFindCertificateInStore(
            cert_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            0x80007,  # CERT_FIND_SUBJECT_CERT
            ctypes.byref(signer_buf),
            None,
        )

        if not cert_context:
            return {"signer": "N/A", "issuer": "N/A"}

        try:
            # Get subject name (signer)
            name_buf = ctypes.create_unicode_buffer(256)
            _CertGetNameStringW(
                cert_context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                name_buf,
                256,
            )
            signer = name_buf.value or "N/A"

            # Get issuer name
            _CertGetNameStringW(
                cert_context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG_VAL,
                None,
                name_buf,
                256,
            )
            issuer = name_buf.value or "N/A"

            return {"signer": signer, "issuer": issuer}
        finally:
            _CertFreeCertificateContext(cert_context)
    finally:
        if crypt_msg:
            _CryptMsgClose(crypt_msg)
        if cert_store:
            _CertCloseStore(cert_store, 0)
