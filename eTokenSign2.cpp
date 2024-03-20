/*
	Copyright 2018, panagenda

	Except where otherwise noted, this work is licensed under https://creativecommons.org/licenses/by-sa/4.0
	It is a derivative work based on code from "draketb" at	https://stackoverflow.com/a/47894907
	_________________
	
	Blog post with some background can be found at https://www.panagenda.com/blog/ev-code-signing-with-ci-cd/
*/


#include <windows.h>
#include <cryptuiapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <functional>
#pragma comment (lib, "cryptui.lib")
#pragma comment (lib, "crypt32.lib")

template<typename T>
class CustomAutoHandle
{
private:
	T	m_handle;
	std::function<void(T&)>	m_deleter;
public:
	operator bool(void) const
	{
		return (m_handle != NULL) && (m_handle != INVALID_HANDLE_VALUE);
	}
	operator T(void) const
	{
		return m_handle;
	}
public:
	CustomAutoHandle(T handle, std::function<void(T&)> f_deleter)
		: m_handle(handle), m_deleter(f_deleter)
	{
	}
	~CustomAutoHandle(void)
	{
		if (operator bool())
		{
			T	Handle = m_handle;
			m_handle = NULL;
			m_deleter(Handle);
		}//if
	}
};//template CustomAutoHandle

const std::wstring ETOKEN_BASE_CRYPT_PROV_NAME = L"eToken Base Cryptographic Provider";

std::string utf16_to_utf8(const std::wstring& str)
{
    if (str.empty())
    {
        return "";
    }

    auto utf8len = ::WideCharToMultiByte(CP_UTF8, 0, str.data(), str.size(), NULL, 0, NULL, NULL);
    if (utf8len == 0)
    {
        return "";
    }

    std::string utf8Str;
    utf8Str.resize(utf8len);
    ::WideCharToMultiByte(CP_UTF8, 0, str.data(), str.size(), &utf8Str[0], utf8Str.size(), NULL, NULL);

    return utf8Str;
}

struct CryptProvHandle
{
    HCRYPTPROV Handle = NULL;
    CryptProvHandle(HCRYPTPROV handle = NULL) : Handle(handle) {}
    ~CryptProvHandle() { if (Handle) ::CryptReleaseContext(Handle, 0); }
};

bool token_logon(const std::wstring& tokenNum, const std::string& tokenPin)
{
    CryptProvHandle cryptProv;
	std::wstring tokenName = L"\\\\.\\AKS ifdh " + tokenNum;
    if (!::CryptAcquireContext(&cryptProv.Handle, tokenName.c_str(), ETOKEN_BASE_CRYPT_PROV_NAME.c_str(), PROV_RSA_FULL, CRYPT_SILENT))
    {
        std::wcerr << L"CryptAcquireContext failed, error " << std::hex << std::showbase << ::GetLastError() << L"\n";
        return NULL;
    }

    if (!::CryptSetProvParam(cryptProv.Handle, PP_SIGNATURE_PIN, reinterpret_cast<const BYTE*>(tokenPin.c_str()), 0))
    {
        std::wcerr << L"CryptSetProvParam failed, error " << std::hex << std::showbase << ::GetLastError() << L"\n";
        return NULL;
    }

	bool result = cryptProv.Handle != NULL;
    cryptProv.Handle = NULL;
    return result;
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 5)
	{
		std::wcerr << L"usage: etokensign.exe <certificate name> <token PIN> <timestamp URL> <path to file to sign>\n";
		std::wcerr << L"(C) 2018 panagenda GmbH\n";
		return 1;
	}

	const std::wstring certName = argv[1];
	const std::wstring tokenPin = argv[2];
	const std::wstring timestampUrl = argv[3];
	const std::wstring fileToSign = argv[4];
	const std::wstring tokenNumber = L"0";

	if (!token_logon(tokenNumber, utf16_to_utf8(tokenPin)))
	{
		return 1;
	}

	//-------------------------------------------------------------------
	// Declare and initialize variables.
	PCCERT_CONTEXT  pDesiredCert = NULL;   // Set to NULL for the first call to CertFindCertificateInStore.

	//-------------------------------------------------------------------
	// Open the certificate store to be searched.

	CustomAutoHandle<HCERTSTORE> hSystemStore(
		CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			0,                      // Encoding type not needed with this PROV.
			NULL,                   // Accept the default HCRYPTPROV.
			CERT_SYSTEM_STORE_CURRENT_USER, // Set the system store location in the registry.
			L"MY"					// Could have used other predefined system stores including Trust, CA, or Root.
		),
		[] (HCERTSTORE& h_cs) {CertCloseStore(h_cs, CERT_CLOSE_STORE_CHECK_FLAG);}
	);
	if (!hSystemStore)                 
	{
		std::wcerr << L"Could not open the MY system store.\n";
		return 1;
	}

	bool bFound = false;
	DWORD cbSize = 0;
	while (!bFound && (pDesiredCert = CertEnumCertificatesInStore(hSystemStore, pDesiredCert)))
	{
		if (!(cbSize = CertGetNameString(pDesiredCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0)))
		{
			std::wcerr << L"Error on getting name size. Continue with next certificate.\n";
			continue;
		}
		std::vector<TCHAR> pszName(cbSize);
		if (!CertGetNameString(pDesiredCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &pszName[0], cbSize))
		{
			std::wcerr << L"Error on getting name. Continue with next certificate.\n";
			continue;
		}
		if (certName.compare(&pszName[0]) == 0)
		{
			bFound = true;
			break;
		}
	}
	if (!bFound)
	{
		std::wcerr << L"No matching certificate to sign found\n";
		return 1;
	}

    CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO extInfo = {};
    extInfo.dwSize = sizeof(extInfo);
    extInfo.pszHashAlg = szOID_NIST_sha256; // Use SHA256 instead of default SHA1

    CRYPTUI_WIZ_DIGITAL_SIGN_INFO signInfo = {};
    signInfo.dwSize = sizeof(signInfo);
    signInfo.dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE;
    signInfo.pwszFileName = fileToSign.c_str();
	signInfo.dwSigningCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_CERT;
	signInfo.pSigningCertContext = pDesiredCert;
    signInfo.pwszTimestampURL = timestampUrl.c_str();
    signInfo.pSignExtInfo = &extInfo;

	int rv = 0;
    if (!::CryptUIWizDigitalSign(CRYPTUI_WIZ_NO_UI, NULL, NULL, &signInfo, NULL))
    {
        std::wcerr << L"CryptUIWizDigitalSign failed, error " << std::hex << std::showbase << ::GetLastError() << L"\n";
        rv = 1;
    }
	else
	{
		std::wcout << L"Successfully signed " << fileToSign << L"\n";
	}

	//-------------------------------------------------------------------
	// Clean up.
	if (pDesiredCert)
	{
		CertFreeCertificateContext(pDesiredCert);
	}

    return rv;
}
