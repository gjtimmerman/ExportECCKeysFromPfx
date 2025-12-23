// ExportEccPrivateKeyUsingSymmetricEncryption.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>


int evaluateBStatus(NTSTATUS status)
{
	if (status == ERROR_SUCCESS)
		return 0;
	fprintf(stderr, "BCrypt error code: 0x%08X\n", status);
	switch (status)
	{
	case STATUS_INVALID_HANDLE:
		fprintf(stderr, "Cryptographic functionr returned error code: STATUS_INVALID_HANDLE");
		return 1;
	case STATUS_INVALID_PARAMETER:
		fprintf(stderr, "Cryptographic function returned error code: STATUS_INVALID_PARAMETER");
		return 1;
	case STATUS_NO_MEMORY:
		fprintf(stderr, "Cryptographic function returned error code: STATUS_NO_MEMORY");
		return 1;

	default:
		fprintf(stderr, "Cryptographic function returned unknown error code");
		return 1;

	}

}


int evaluateStatus(SECURITY_STATUS status)
{
	if (status == ERROR_SUCCESS)
		return 0;
	fprintf(stderr, "Cryptographic function returned error code: 0x%08X\n", status);
	switch (status)
	{
	case NTE_INVALID_HANDLE:
		fprintf(stderr, "Cryptographic functionr returned error code: NTE_INVALID_HANDLE");
		return 1;
	case NTE_INVALID_PARAMETER:
		fprintf(stderr, "Cryptographic function returned error code: NTE_INVALID_PARAMETER");
		return 1;
	case NTE_BAD_FLAGS:
		fprintf(stderr, "Cryptographic function returned error code: NTE_BAD_FLAGS");
		return 1;
	case NTE_BAD_KEYSET:
		fprintf(stderr, "Cryptographic function returned error code: NTE_BAD_KEYSET");
		return 1;
	case NTE_BAD_KEY_STATE:
		fprintf(stderr, "NTE_BAD_KEY_STATE\n");
		return 1;
	case NTE_BAD_TYPE:
		fprintf(stderr, "NTE_BAD_TYPE\n");
		return 1;
	case NTE_PERM:
		fprintf(stderr, "NTE_PERM - Access denied\n");
		return 1;

	case NTE_NOT_SUPPORTED:
		fprintf(stderr, "Cryptographic function returned error code: NTE_NOT_SUPPORTED");
		return 1;

	default:
		fprintf(stderr, "Cryptographic function returned unknown error code");
		return 1;

	}

}
int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		std::cout << "Usage: " << argv[0] << " filename password" << std::endl;
		return -1;
	}
	wchar_t* wideFileName = new wchar_t[strlen(argv[1]) + 1];
	size_t numBytes;
	mbstowcs_s(&numBytes, wideFileName, (size_t)strlen(argv[1]) + 1, argv[1], (size_t)strlen(argv[1]));
	fprintf(stderr, "Searching for certificate file with name: %S\n", wideFileName);
	wchar_t* password = new wchar_t[strlen(argv[2]) + 1];
	mbstowcs_s(&numBytes, password, (size_t)strlen(argv[2]) + 1, argv[2], (size_t)strlen(argv[2]));
	HANDLE hFile = CreateFile(wideFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Failed to open file %S\n", wideFileName);
		delete[] wideFileName;
		delete[] password;
		return -1;
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	BYTE* fileData = new BYTE[fileSize];
	DWORD bytesRead;
	if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
	{
		fprintf(stderr, "Failed to read file %S\n", wideFileName);
		delete[] wideFileName;
		delete[] password;
		delete[] fileData;
		CloseHandle(hFile);
		return -1;
	}
	DWORD decodedSize = 0;

	// Manual PKCS#12 parsing - parse the complete structure from the beginning
	fprintf(stderr, "=== Parsing PKCS#12 PFX Structure ===\n");

	// Step 1: Parse the outer PFX SEQUENCE
	// PFX ::= SEQUENCE {
	//   version    INTEGER {v3(3)}(v3,...),
	//   authSafe   ContentInfo,
	//   macData    MacData OPTIONAL
	// }

	// The file starts with a SEQUENCE tag
	// Let's manually parse the ASN.1 structure

	BYTE* p = fileData;
	DWORD remaining = fileSize;

	// Check for SEQUENCE tag (0x30)
	if (p[0] != 0x30)
	{
		fprintf(stderr, "Invalid PFX: doesn't start with SEQUENCE tag\n");
		delete[] wideFileName;
		delete[] password;
		delete[] fileData;
		CloseHandle(hFile);
		return -1;
	}

	fprintf(stderr, "Found PFX SEQUENCE at offset 0\n");

	// Parse length
	DWORD seqLength = 0;
	DWORD headerSize = 2;

	if (p[1] & 0x80)
	{
		// Long form length
		DWORD numLengthBytes = p[1] & 0x7F;
		headerSize = 2 + numLengthBytes;
		for (DWORD i = 0; i < numLengthBytes; i++)
		{
			seqLength = (seqLength << 8) | p[2 + i];
		}
		fprintf(stderr, "PFX SEQUENCE length: %d bytes (long form, %d length bytes)\n", seqLength, numLengthBytes);
	}
	else
	{
		// Short form length
		seqLength = p[1];
		fprintf(stderr, "PFX SEQUENCE length: %d bytes (short form)\n", seqLength);
	}

	p += headerSize;
	remaining -= headerSize;

	// Parse version (INTEGER)
	if (p[0] != 0x02)
	{
		fprintf(stderr, "Expected INTEGER tag for version, got 0x%02X\n", p[0]);
	}
	else
	{
		DWORD versionLen = p[1];
		DWORD version = 0;
		for (DWORD i = 0; i < versionLen; i++)
		{
			version = (version << 8) | p[2 + i];
		}
		fprintf(stderr, "PFX version: %d\n", version);

		p += 2 + versionLen;
		remaining -= 2 + versionLen;
	}

	// Now p points to the authSafe ContentInfo
	fprintf(stderr, "AuthSafe ContentInfo starts at offset %lld\n", (LONGLONG)(p - fileData));
	fprintf(stderr, "Next tag: 0x%02X (should be 0x30 for SEQUENCE)\n", p[0]);

	// Parse the authSafe ContentInfo using Windows decoder
	CRYPT_CONTENT_INFO* pAuthSafeContent = NULL;
	DWORD authSafeContentSize = 0;

	if (!CryptDecodeObjectEx(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		PKCS_CONTENT_INFO,
		p,
		remaining,
		CRYPT_DECODE_ALLOC_FLAG,
		NULL,
		&pAuthSafeContent,
		&authSafeContentSize
	))
	{
		fprintf(stderr, "Failed to decode AuthSafe ContentInfo. Error: 0x%08X\n", GetLastError());
		delete[] wideFileName;
		delete[] password;
		delete[] fileData;
		CloseHandle(hFile);
		return -1;
	}

	fprintf(stderr, "AuthSafe ContentInfo OID: %s\n", pAuthSafeContent->pszObjId);
	fprintf(stderr, "AuthSafe Content size: %d bytes\n", pAuthSafeContent->Content.cbData);

	// The rest of your code continues here...
	// Decode the PKCS7 data (OCTET STRING)
	CRYPT_DATA_BLOB* pDataBlob = NULL;
	DWORD dataBlobSize = 0;

	if (!CryptDecodeObjectEx(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		X509_OCTET_STRING,
		pAuthSafeContent->Content.pbData,
		pAuthSafeContent->Content.cbData,
		CRYPT_DECODE_ALLOC_FLAG,
		NULL,
		&pDataBlob,
		&dataBlobSize
	))
	{
		fprintf(stderr, "Failed to decode PKCS7 data. Error: 0x%08X\n", GetLastError());
		LocalFree(pAuthSafeContent);
		delete[] wideFileName;
		delete[] password;
		delete[] fileData;
		CloseHandle(hFile);
		return -1;
	}

	fprintf(stderr, "Decoded AuthSafe data: %d bytes\n", pDataBlob->cbData);
	fprintf(stderr, "Decoded AuthSafe data: %d bytes\n", pDataBlob->cbData);

	// Parse as SEQUENCE OF ANY to get individual SafeContents
	typedef struct {
		DWORD cValue;
		PCRYPT_DER_BLOB rgValue;
	} CONTENT_INFO_SEQUENCE;

	CONTENT_INFO_SEQUENCE* pAuthSafe = NULL;
	DWORD authSafeSize = 0;

	if (!CryptDecodeObjectEx(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		X509_SEQUENCE_OF_ANY,
		pDataBlob->pbData,
		pDataBlob->cbData,
		CRYPT_DECODE_ALLOC_FLAG,
		NULL,
		&pAuthSafe,
		&authSafeSize
	))
	{
		fprintf(stderr, "Failed to decode AuthSafe sequence. Error: 0x%08X\n", GetLastError());
		LocalFree(pDataBlob);
		LocalFree(pAuthSafeContent);
		delete[] wideFileName;
		delete[] password;
		delete[] fileData;
		CloseHandle(hFile);
		return -1;
	}

	fprintf(stderr, "AuthSafe contains %d SafeContents\n", pAuthSafe->cValue);

	// Iterate through SafeContents to find encrypted private key
	for (DWORD i = 0; i < pAuthSafe->cValue; i++)
	{
		fprintf(stderr, "\n=== SafeContent %d ===\n", i);

		CRYPT_CONTENT_INFO* pSafeContent = NULL;
		DWORD safeContentSize = 0;

		if (!CryptDecodeObjectEx(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			PKCS_CONTENT_INFO,
			pAuthSafe->rgValue[i].pbData,
			pAuthSafe->rgValue[i].cbData,
			CRYPT_DECODE_ALLOC_FLAG,
			NULL,
			&pSafeContent,
			&safeContentSize
		))
		{
			fprintf(stderr, "Failed to decode SafeContent %d\n", i);
			continue;
		}

		fprintf(stderr, "Content Type OID: %s\n", pSafeContent->pszObjId);
		fprintf(stderr, "Content Size: %d bytes\n", pSafeContent->Content.cbData);

		// Check if it's encrypted data (id-encryptedData = 1.2.840.113549.1.7.6)
		if (strcmp(pSafeContent->pszObjId, "1.2.840.113549.1.7.6") == 0)
		{
			fprintf(stderr, "*** This is ENCRYPTED DATA (contains private key) ***\n");

			// The content is an EncryptedData structure
			// We need to parse it manually to extract encryption parameters and encrypted content

			BYTE* encData = pSafeContent->Content.pbData;
			DWORD encDataLen = pSafeContent->Content.cbData;

			fprintf(stderr, "\n=== Manual ASN.1 Parsing of EncryptedData ===\n");

			// EncryptedData ::= SEQUENCE {
			//   version Version,
			//   encryptedContentInfo EncryptedContentInfo
			// }

			BYTE* ep = encData;

			// Skip SEQUENCE tag and length
			if (ep[0] == 0x30)
			{
				DWORD seqLen = 0;
				DWORD seqHdrSize = 2;
				if (ep[1] & 0x80)
				{
					DWORD lenBytes = ep[1] & 0x7F;
					for (DWORD j = 0; j < lenBytes; j++)
						seqLen = (seqLen << 8) | ep[2 + j];
					seqHdrSize = 2 + lenBytes;
				}
				else
				{
					seqLen = ep[1];
				}

				fprintf(stderr, "EncryptedData SEQUENCE length: %d\n", seqLen);
				ep += seqHdrSize;

				// Parse version (INTEGER)
				if (ep[0] == 0x02)
				{
					DWORD verLen = ep[1];
					DWORD ver = 0;
					for (DWORD j = 0; j < verLen; j++)
						ver = (ver << 8) | ep[2 + j];
					fprintf(stderr, "EncryptedData version: %d\n", ver);
					ep += 2 + verLen;
				}

				// Now we should have EncryptedContentInfo SEQUENCE
				fprintf(stderr, "EncryptedContentInfo at offset %lld, tag: 0x%02X\n",
					(LONGLONG)(ep - encData), ep[0]);
			}

		}
		else if (strcmp(pSafeContent->pszObjId, "1.2.840.113549.1.7.1") == 0)
		{
			fprintf(stderr, "This is PLAIN DATA (likely certificates)\n");

			// Decode the OCTET STRING containing SafeBags
			CRYPT_DATA_BLOB* pPlainData = NULL;
			DWORD plainDataSize = 0;

			if (!CryptDecodeObjectEx(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				X509_OCTET_STRING,
				pSafeContent->Content.pbData,
				pSafeContent->Content.cbData,
				CRYPT_DECODE_ALLOC_FLAG,
				NULL,
				&pPlainData,
				&plainDataSize
			))
			{
				fprintf(stderr, "Failed to decode plain data OCTET STRING. Error: 0x%08X\n", GetLastError());
				LocalFree(pSafeContent);
				continue;
			}

			fprintf(stderr, "Plain data size: %d bytes\n", pPlainData->cbData);

			// The plain data contains a SEQUENCE of SafeBags
			// SafeBag ::= SEQUENCE {
			//   bagId       OBJECT IDENTIFIER,
			//   bagValue    [0] EXPLICIT ANY DEFINED BY bagId,
			//   bagAttributes SET OF PKCS12Attribute OPTIONAL
			// }

			// Parse as SEQUENCE OF ANY to get individual SafeBags
			CONTENT_INFO_SEQUENCE* pSafeBags = NULL;
			DWORD safeBagsSize = 0;

			if (!CryptDecodeObjectEx(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				X509_SEQUENCE_OF_ANY,
				pPlainData->pbData,
				pPlainData->cbData,
				CRYPT_DECODE_ALLOC_FLAG,
				NULL,
				&pSafeBags,
				&safeBagsSize
			))
			{
				fprintf(stderr, "Failed to decode SafeBags. Error: 0x%08X\n", GetLastError());
				LocalFree(pPlainData);
				LocalFree(pSafeContent);
				continue;
			}

			fprintf(stderr, "Found %d SafeBag(s) in plain data\n", pSafeBags->cValue);

			// Iterate through SafeBags
			for (DWORD bagIdx = 0; bagIdx < pSafeBags->cValue; bagIdx++)
			{
				fprintf(stderr, "\n  --- SafeBag %d ---\n", bagIdx);

				BYTE* bagData = pSafeBags->rgValue[bagIdx].pbData;
				DWORD bagLen = pSafeBags->rgValue[bagIdx].cbData;

				// Parse SafeBag structure manually
				if (bagData[0] == 0x30) // SEQUENCE
				{
					BYTE* bp = bagData;

					// Skip SEQUENCE header
					DWORD seqHdrSize = 2;
					if (bp[1] & 0x80)
					{
						DWORD lenBytes = bp[1] & 0x7F;
						seqHdrSize = 2 + lenBytes;
					}
					bp += seqHdrSize;

					// Parse bagId (OBJECT IDENTIFIER)
					if (bp[0] == 0x06) // OID tag
					{
						DWORD oidLen = bp[1];

						// Decode OID manually or use Windows
						LPSTR* pszOid = NULL;
						DWORD oidStrLen = 0;

						// Try to decode the OID
						if (CryptDecodeObjectEx(
							X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
							X509_OBJECT_IDENTIFIER,
							bp,
							2 + oidLen,
							CRYPT_DECODE_ALLOC_FLAG,
							NULL,
							&pszOid,
							&oidStrLen
						))
						{
							fprintf(stderr, "  BagId OID: %s\n", *pszOid);

							// Check if it's a pkcs8ShroudedKeyBag (1.2.840.113549.1.12.10.1.2)
							if (strcmp(*pszOid, "1.2.840.113549.1.12.10.1.2") == 0)
							{
								fprintf(stderr, "  Type: PKCS#8 Shrouded Key Bag (Encrypted Private Key)\n");

								bp += 2 + oidLen;

								// Next should be [0] EXPLICIT tag containing EncryptedPrivateKeyInfo
								if (bp[0] == 0xA0) // [0] EXPLICIT
								{
									// Skip [0] tag and length
									DWORD explicitHdrSize = 2;
									if (bp[1] & 0x80)
									{
										DWORD lenBytes = bp[1] & 0x7F;
										explicitHdrSize = 2 + lenBytes;
									}
									bp += explicitHdrSize;

									fprintf(stderr, "  Parsing EncryptedPrivateKeyInfo...\n");

									// The remaining data is EncryptedPrivateKeyInfo
									DWORD encPrivKeyLen = (DWORD)(bagData + bagLen - bp);

									// Try to decode as PKCS_ENCRYPTED_PRIVATE_KEY_INFO
									CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* pEncPrivKeyInfo = NULL;
									DWORD encPrivKeyInfoSize = 0;

									if (CryptDecodeObjectEx(
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										PKCS_ENCRYPTED_PRIVATE_KEY_INFO,
										bp,
										encPrivKeyLen,
										CRYPT_DECODE_ALLOC_FLAG,
										NULL,
										&pEncPrivKeyInfo,
										&encPrivKeyInfoSize
									))
									{
										fprintf(stderr, "  Successfully decoded EncryptedPrivateKeyInfo\n");
										fprintf(stderr, "  Encryption Algorithm: %s\n", pEncPrivKeyInfo->EncryptionAlgorithm.pszObjId);
										fprintf(stderr, "  Encrypted Data Size: %d bytes\n", pEncPrivKeyInfo->EncryptedPrivateKey.cbData);
										// Save the entire EncryptedPrivateKeyInfo structure to a file
										// This includes the algorithm identifier, parameters, and encrypted data
										if (bp[0] != 0x30)
										{
											fprintf(stderr, "Invalid: doesn't start with SEQUENCE tag\n");
										}
										else
										{
											DWORD seqLength = 0;
											DWORD headerSize;
											if (bp[1] & 0x80)
											{
												// Long form length
												DWORD numLengthBytes = bp[1] & 0x7F;
												headerSize = 2 + numLengthBytes;
												for (DWORD i = 0; i < numLengthBytes; i++)
												{
													seqLength = (seqLength << 8) | bp[2 + i];
												}
												fprintf(stderr, "  PFX SEQUENCE length: %d bytes (long form, %d length bytes)\n", seqLength, numLengthBytes);
											}
											else
											{
												// Short form length
												seqLength = bp[1];
												fprintf(stderr, "  PFX SEQUENCE length: %d bytes (short form)\n", seqLength);
											}
											seqLength += headerSize;

											HANDLE hEncryptedKeyFile = CreateFile(L"encrypted_private_key_info.der",
												GENERIC_WRITE,
												0,
												NULL,
												CREATE_ALWAYS,
												FILE_ATTRIBUTE_NORMAL,
												NULL);

											if (hEncryptedKeyFile != INVALID_HANDLE_VALUE)
											{
												DWORD written = 0;
												// Write the complete EncryptedPrivateKeyInfo structure
												// bp points to the start, seqLenght is the total length
												if (WriteFile(hEncryptedKeyFile,
													bp,
													seqLength,
													&written,
													NULL))
												{
													fprintf(stderr, "  Saved complete EncryptedPrivateKeyInfo to encrypted_private_key_info.der (%d bytes)\n", written);
													fprintf(stderr, "    This file contains: algorithm OID, PBES2 parameters (salt, iterations, IV), and encrypted data\n");
												}
												else
												{
													fprintf(stderr, "  Failed to write EncryptedPrivateKeyInfo: 0x%08X\n", GetLastError());
												}
												CloseHandle(hEncryptedKeyFile);
											}
											else
											{
												fprintf(stderr, "  Failed to create EncryptedPrivateKeyInfo file: 0x%08X\n", GetLastError());
											}
										}
										// Parse the PBE parameters
										CRYPT_ALGORITHM_IDENTIFIER* pPbeAlg = &pEncPrivKeyInfo->EncryptionAlgorithm;										if (pPbeAlg->Parameters.cbData > 0)
										{
											fprintf(stderr, "  PBE Parameters Size: %d bytes\n", pPbeAlg->Parameters.cbData);

											// Parse PKCS#12 PBE parameters (salt and iterations)
											BYTE* pParams = pPbeAlg->Parameters.pbData;

											// Should be a SEQUENCE
											if (pParams[0] == 0x30)
											{
												DWORD paramPos = 2; // Skip SEQUENCE tag and length

												// Check what's inside - might be another SEQUENCE
												fprintf(stderr, "  Inside PBE params, tag: 0x%02X\n", pParams[paramPos]);

												if (pParams[paramPos] == 0x30) // Another SEQUENCE
												{
													fprintf(stderr, "  Found nested SEQUENCE in PBE parameters\n");

													// Skip nested SEQUENCE header
													DWORD nestedSeqLen = pParams[paramPos + 1];
													paramPos += 2; // Move past SEQUENCE tag and length

													// Now parse what's inside this nested SEQUENCE
													fprintf(stderr, "  Nested SEQUENCE tag at paramPos: 0x%02X\n", pParams[paramPos]);

													// Check if it's an OID first
													if (pParams[paramPos] == 0x06) // OID
													{
														DWORD oidLen = pParams[paramPos + 1];

														fprintf(stderr, "  Found OID in nested SEQUENCE (length %d)\n", oidLen);

														// Decode the OID
														LPSTR* pNestedOid = NULL;
														DWORD nestedOidStrLen = 0;

														if (CryptDecodeObjectEx(
															X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
															X509_OBJECT_IDENTIFIER,
															&pParams[paramPos],
															2 + oidLen,
															CRYPT_DECODE_ALLOC_FLAG,
															NULL,
															&pNestedOid,
															&nestedOidStrLen
														))
														{
															fprintf(stderr, "  Algorithm OID: %s\n", *pNestedOid);
															LocalFree(pNestedOid);
														}

														paramPos += 2 + oidLen;

														fprintf(stderr, "  Next tag after OID: 0x%02X\n", pParams[paramPos]);

														// Parse the PBKDF2 parameters SEQUENCE
														if (pParams[paramPos] == 0x30) // PBKDF2-params SEQUENCE
														{
															fprintf(stderr, "  Found PBKDF2 parameters SEQUENCE\n");

															// Skip SEQUENCE header
															DWORD pbkdf2SeqLen = pParams[paramPos + 1];
															paramPos += 2;

															fprintf(stderr, "  PBKDF2 params first tag: 0x%02X\n", pParams[paramPos]);

															// PBKDF2-params ::= SEQUENCE {
															//   salt OCTET STRING,
															//   iterationCount INTEGER,
															//   keyLength INTEGER OPTIONAL,
															//   prf AlgorithmIdentifier OPTIONAL
															// }

															// Parse salt (OCTET STRING)
															if (pParams[paramPos] == 0x04)
															{
																DWORD saltLen = pParams[paramPos + 1];
																BYTE* salt = &pParams[paramPos + 2];

																fprintf(stderr, "  Salt (%d bytes): ", saltLen);
																for (DWORD s = 0; s < saltLen && s < 20; s++)
																	fprintf(stderr, "%02X", salt[s]);
																fprintf(stderr, "\n");

																paramPos += 2 + saltLen;

																// Parse iteration count (INTEGER)
																if (pParams[paramPos] == 0x02)
																{
																	DWORD iterLen = pParams[paramPos + 1];
																	DWORD iterations = 0;
																	for (DWORD it = 0; it < iterLen; it++)
																	{
																		iterations = (iterations << 8) | pParams[paramPos + 2 + it];
																	}

																	fprintf(stderr, "  Iterations: %d\n", iterations);
																	paramPos += 2 + iterLen;

																	// Optional: keyLength (INTEGER)
																	if (pParams[paramPos] == 0x02)
																	{
																		DWORD keyLenLen = pParams[paramPos + 1];
																		DWORD keyLength = 0;
																		for (DWORD kl = 0; kl < keyLenLen; kl++)
																		{
																			keyLength = (keyLength << 8) | pParams[paramPos + 2 + kl];
																		}
																		fprintf(stderr, "  Key length: %d bytes\n", keyLength);
																		paramPos += 2 + keyLenLen;
																	}

																	// Optional: PRF (AlgorithmIdentifier SEQUENCE)
																	if (pParams[paramPos] == 0x30)
																	{
																		fprintf(stderr, "  Found PRF AlgorithmIdentifier SEQUENCE\n");

																		// Skip SEQUENCE header
																		DWORD prfSeqLen = pParams[paramPos + 1];
																		paramPos += 2;

																		// Parse PRF OID
																		if (pParams[paramPos] == 0x06)
																		{
																			DWORD prfOidLen = pParams[paramPos + 1];

																			// Decode PRF OID
																			LPSTR* pPrfOid = NULL;
																			DWORD prfOidStrLen = 0;

																			if (CryptDecodeObjectEx(
																				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																				X509_OBJECT_IDENTIFIER,
																				&pParams[paramPos],
																				2 + prfOidLen,
																				CRYPT_DECODE_ALLOC_FLAG,
																				NULL,
																				&pPrfOid,
																				&prfOidStrLen
																			))
																			{
																				fprintf(stderr, "  PRF Algorithm OID: %s\n", *pPrfOid);
																				LocalFree(pPrfOid);
																			}

																			paramPos += 2 + prfOidLen;

																			// PRF may have parameters (usually NULL for HMAC)
																			if (pParams[paramPos] == 0x05) // NULL tag
																			{
																				fprintf(stderr, "  PRF has NULL parameters\n");
																				paramPos += 2; // Skip NULL tag and length
																			}
																		}
																	}

																	fprintf(stderr, "\n  *** Successfully parsed PBKDF2 parameters ***\n");
																	fprintf(stderr, "  This uses PBES2 (PKCS#5 v2.0) encryption scheme\n");

																	// Now parse the encryption scheme (second part of PBES2-params)
																	// We need to go back to after the first nested SEQUENCE in PBES2
																	// The structure is: PBES2-params ::= SEQUENCE {
																	//   keyDerivationFunc AlgorithmIdentifier,  -- Already parsed
																	//   encryptionScheme AlgorithmIdentifier    -- Parse this now
																	// }

																	// We need to find where we are in the outer PBES2 params
																	// Let's reparse from the beginning of the outer params
																	fprintf(stderr, "\n  === Parsing Encryption Scheme ===\n");

																	// Reset to beginning of PBE params
																	DWORD encSchemePos = 2; // Skip outer SEQUENCE tag and length

																	// Skip first SEQUENCE (PBKDF2)
																	if (pParams[encSchemePos] == 0x30)
																	{
																		DWORD kdfSeqLen = pParams[encSchemePos + 1];
																		if (pParams[encSchemePos + 1] & 0x80)
																		{
																			// Long form
																			DWORD numLenBytes = pParams[encSchemePos + 1] & 0x7F;
																			kdfSeqLen = 0;
																			for (DWORD lb = 0; lb < numLenBytes; lb++)
																			{
																				kdfSeqLen = (kdfSeqLen << 8) | pParams[encSchemePos + 2 + lb];
																			}
																			encSchemePos += 2 + numLenBytes + kdfSeqLen;
																		}
																		else
																		{
																			encSchemePos += 2 + kdfSeqLen;
																		}

																		fprintf(stderr, "  Encryption scheme starts at offset %d, tag: 0x%02X\n",
																			encSchemePos, pParams[encSchemePos]);

																		// Now parse the encryption scheme AlgorithmIdentifier
																		if (pParams[encSchemePos] == 0x30) // SEQUENCE
																		{
																			fprintf(stderr, "  Found Encryption Scheme SEQUENCE\n");

																			// Skip SEQUENCE header
																			DWORD encSchemeSeqLen = pParams[encSchemePos + 1];
																			encSchemePos += 2;

																			// Parse encryption algorithm OID
																			if (pParams[encSchemePos] == 0x06)
																			{
																				DWORD encOidLen = pParams[encSchemePos + 1];

																				LPSTR* pEncOid = NULL;
																				DWORD encOidStrLen = 0;

																				if (CryptDecodeObjectEx(
																					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																					X509_OBJECT_IDENTIFIER,
																					&pParams[encSchemePos],
																					2 + encOidLen,
																					CRYPT_DECODE_ALLOC_FLAG,
																					NULL,
																					&pEncOid,
																					&encOidStrLen
																				))
																				{
																					fprintf(stderr, "  Encryption Algorithm OID: %s\n", *pEncOid);

																					// Common encryption OIDs:
																					// 2.16.840.1.101.3.4.1.2 = AES-128-CBC
																					// 2.16.840.1.101.3.4.1.42 = AES-256-CBC
																					// 1.2.840.113549.3.7 = DES-EDE3-CBC (3DES)

																					LocalFree(pEncOid);
																				}

																				encSchemePos += 2 + encOidLen;

																				// Parse IV (OCTET STRING)
																				if (pParams[encSchemePos] == 0x04)
																				{
																					DWORD ivLen = pParams[encSchemePos + 1];
																					BYTE* iv = &pParams[encSchemePos + 2];

																					fprintf(stderr, "  IV (%d bytes): ", ivLen);
																					for (DWORD ivIdx = 0; ivIdx < ivLen && ivIdx < 32; ivIdx++)
																						fprintf(stderr, "%02X", iv[ivIdx]);
																					fprintf(stderr, "\n");

																					fprintf(stderr, "\n  *** Successfully parsed complete PBES2 parameters ***\n");
																					fprintf(stderr, "  You now have all parameters needed to decrypt the private key:\n");
																					fprintf(stderr, "  1. Use PBKDF2 with the salt, iterations, and HMAC-SHA256\n");
																					fprintf(stderr, "  2. Derive the encryption key from your password\n");
																					fprintf(stderr, "  3. Decrypt the encrypted data using the cipher algorithm and IV\n");
																					fprintf(stderr, "  4. The result will be a PKCS#8 PrivateKeyInfo structure\n");

																					// Now perform the actual decryption
																					fprintf(stderr, "\n  === Decrypting Private Key ===\n");

																					// Step 1: Convert password from wchar_t to UTF-8 bytes
																					int pwdLen = WideCharToMultiByte(CP_UTF8, 0, password, -1, NULL, 0, NULL, NULL);
																					char* utf8Password = new char[pwdLen];
																					WideCharToMultiByte(CP_UTF8, 0, password, -1, utf8Password, pwdLen, NULL, NULL);

																					// Step 2: Derive key using PBKDF2 with BCrypt
																					BCRYPT_ALG_HANDLE hAlg = NULL;
																					NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
																					if (status != 0)
																					{
																						fprintf(stderr, "  Failed to open BCrypt algorithm provider: 0x%08X\n", status);
																					}
																					else
																					{
																						// Derive the encryption key
																						BYTE derivedKey[32]; // 256 bits for AES-256 or key length from params
																						DWORD keyLengthToDeriveBytes = 32; // Default to 32 bytes (256 bits)

																						// If keyLength was specified in PBKDF2 params, use that
																						// (we stored it earlier if present)

																						status = BCryptDeriveKeyPBKDF2(
																							hAlg,
																							(PUCHAR)utf8Password,
																							(ULONG)(strlen(utf8Password)),
																							salt,
																							saltLen,
																							iterations,
																							derivedKey,
																							keyLengthToDeriveBytes,
																							0
																						);

																						if (status != 0)
																						{
																							fprintf(stderr, "  Failed to derive key using PBKDF2: 0x%08X\n", status);
																						}
																						else
																						{
																							fprintf(stderr, "  Successfully derived encryption key (%d bytes)\n", keyLengthToDeriveBytes);
																							fprintf(stderr, "  Derived key (first 16 bytes): ");
																							for (DWORD dk = 0; dk < 16 && dk < keyLengthToDeriveBytes; dk++)
																								fprintf(stderr, "%02X", derivedKey[dk]);
																							fprintf(stderr, "\n");

																							// Step 3: Decrypt the encrypted private key using the derived key and IV
																							BCRYPT_ALG_HANDLE hAesAlg = NULL;
																							status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);

																							if (status != 0)
																							{
																								fprintf(stderr, "  Failed to open AES algorithm provider: 0x%08X\n", status);
																							}
																							else
																							{
																								// Set chaining mode to CBC
																								status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE,
																									(PBYTE)BCRYPT_CHAIN_MODE_CBC,
																									sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

																								if (status != 0)
																								{
																									fprintf(stderr, "  Failed to set CBC mode: 0x%08X\n", status);
																								}
																								else
																								{
																									// Import the key
																									BCRYPT_KEY_HANDLE hKey = NULL;
																									status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0,
																										derivedKey, keyLengthToDeriveBytes, 0);

																									if (status != 0)
																									{
																										fprintf(stderr, "  Failed to generate symmetric key: 0x%08X\n", status);
																									}
																									else
																									{
																										// Decrypt the data
																										DWORD decryptedSize = 0;
																										status = BCryptDecrypt(hKey,
																											pEncPrivKeyInfo->EncryptedPrivateKey.pbData,
																											pEncPrivKeyInfo->EncryptedPrivateKey.cbData,
																											NULL, iv, ivLen, NULL, 0, &decryptedSize, 0);

																										if (status != 0)
																										{
																											fprintf(stderr, "  Failed to get decrypted size: 0x%08X\n", status);
																										}
																										else
																										{
																											BYTE* decryptedData = new BYTE[decryptedSize];

																											status = BCryptDecrypt(hKey,
																												pEncPrivKeyInfo->EncryptedPrivateKey.pbData,
																												pEncPrivKeyInfo->EncryptedPrivateKey.cbData,
																												NULL, iv, ivLen, decryptedData, decryptedSize, &decryptedSize, 0);

																											if (status != 0)
																											{
																												fprintf(stderr, "  Failed to decrypt data: 0x%08X\n", status);
																											}
																											else
																											{
																												fprintf(stderr, "  Successfully decrypted private key! (%d bytes)\n", decryptedSize);
																												fprintf(stderr, "  Decrypted data (first 32 bytes): ");
																												for (DWORD dd = 0; dd < 32 && dd < decryptedSize; dd++)
																													fprintf(stderr, "%02X", decryptedData[dd]);
																												fprintf(stderr, "\n");
																												HANDLE hFileOut = CreateFile(L"decrypted_private_key.der",
																													GENERIC_WRITE,
																													0,
																													NULL,
																													CREATE_ALWAYS,
																													FILE_ATTRIBUTE_NORMAL,
																													NULL);

																												if (hFileOut != INVALID_HANDLE_VALUE)
																												{
																													DWORD written = 0;
																													if (WriteFile(hFileOut, decryptedData, decryptedSize, &written, NULL))
																													{
																														fprintf(stderr, "  Successfully wrote decrypted private key to file.\n");
																													}
																													else
																													{
																														fprintf(stderr, "  Failed to write decrypted private key to file: 0x%08X\n", GetLastError());
																													}
																													CloseHandle(hFileOut);
																												}
																												else
																												{
																													fprintf(stderr, "  Failed to create output file: 0x%08X\n", GetLastError());
																												}

																												// The decrypted data should be a PKCS#8 PrivateKeyInfo structure
																												fprintf(stderr, "\n  Decrypted data is PKCS#8 PrivateKeyInfo - tag: 0x%02X\n", decryptedData[0]);

																												// Now you can parse the PKCS#8 structure to extract the ECC private key
																												// Or use it directly for re-encryption with AES-256-GCM

																																// The decrypted data should be a PKCS#8 PrivateKeyInfo structure
																												fprintf(stderr, "\n  === Parsing PKCS#8 PrivateKeyInfo ===\n");
																												fprintf(stderr, "  Decrypted data starts with tag: 0x%02X\n", decryptedData[0]);

																												// PKCS#8 PrivateKeyInfo ::= SEQUENCE {
																												//   version INTEGER,
																												//   privateKeyAlgorithm AlgorithmIdentifier,
																												//   privateKey OCTET STRING,
																												//   attributes [0] IMPLICIT Attributes OPTIONAL
																												// }

																												BYTE* pkcs8Ptr = decryptedData;

																												if (pkcs8Ptr[0] == 0x30) // SEQUENCE
																												{
																													// Skip SEQUENCE header
																													DWORD pkcs8SeqLen = pkcs8Ptr[1];
																													DWORD pkcs8HdrSize = 2;
																													if (pkcs8Ptr[1] & 0x80)
																													{
																														DWORD numLen = pkcs8Ptr[1] & 0x7F;
																														pkcs8SeqLen = 0;
																														for (DWORD nl = 0; nl < numLen; nl++)
																															pkcs8SeqLen = (pkcs8SeqLen << 8) | pkcs8Ptr[2 + nl];
																														pkcs8HdrSize = 2 + numLen;
																													}
																													pkcs8Ptr += pkcs8HdrSize;

																													// Parse version (INTEGER)
																													if (pkcs8Ptr[0] == 0x02)
																													{
																														DWORD verLen = pkcs8Ptr[1];
																														DWORD version = 0;
																														for (DWORD v = 0; v < verLen; v++)
																															version = (version << 8) | pkcs8Ptr[2 + v];
																														fprintf(stderr, "  PKCS#8 version: %d\n", version);
																														pkcs8Ptr += 2 + verLen;
																													}

																													// Parse AlgorithmIdentifier SEQUENCE
																													if (pkcs8Ptr[0] == 0x30)
																													{
																														DWORD algSeqLen = pkcs8Ptr[1];
																														fprintf(stderr, "  AlgorithmIdentifier SEQUENCE found\n");
																														pkcs8Ptr += 2;

																														// Parse algorithm OID
																														if (pkcs8Ptr[0] == 0x06)
																														{
																															DWORD algOidLen = pkcs8Ptr[1];

																															LPSTR* pAlgOid = NULL;
																															DWORD algOidStrLen = 0;

																															if (CryptDecodeObjectEx(
																																X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																																X509_OBJECT_IDENTIFIER,
																																pkcs8Ptr,
																																2 + algOidLen,
																																CRYPT_DECODE_ALLOC_FLAG,
																																NULL,
																																&pAlgOid,
																																&algOidStrLen
																															))
																															{
																																fprintf(stderr, "  Private Key Algorithm OID: %s\n", *pAlgOid);
																																// 1.2.840.10045.2.1 = EC Public Key
																																LocalFree(pAlgOid);
																															}

																															pkcs8Ptr += 2 + algOidLen;

																															// Parse curve OID (for ECC)
																															if (pkcs8Ptr[0] == 0x06)
																															{
																																DWORD curveOidLen = pkcs8Ptr[1];

																																LPSTR* pCurveOid = NULL;
																																DWORD curveOidStrLen = 0;

																																if (CryptDecodeObjectEx(
																																	X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
																																	X509_OBJECT_IDENTIFIER,
																																	pkcs8Ptr,
																																	2 + curveOidLen,
																																	CRYPT_DECODE_ALLOC_FLAG,
																																	NULL,
																																	&pCurveOid,
																																	&curveOidStrLen
																																))
																																{
																																	fprintf(stderr, "  Curve OID: %s\n", *pCurveOid);
																																	// 1.2.840.10045.3.1.7 = secp256r1 (P-256)
																																	// 1.3.132.0.34 = secp384r1 (P-384)
																																	// 1.3.132.0.35 = secp521r1 (P-521)
																																	LocalFree(pCurveOid);
																																}

																																pkcs8Ptr += 2 + curveOidLen;
																															}
																														}
																													}

																													// Now parse the private key OCTET STRING
																													if (pkcs8Ptr[0] == 0x04)
																													{
																														DWORD privKeyOctetLen = pkcs8Ptr[1];
																														DWORD privKeyOctetHdrSize = 2;

																														if (pkcs8Ptr[1] & 0x80)
																														{
																															DWORD numLen = pkcs8Ptr[1] & 0x7F;
																															privKeyOctetLen = 0;
																															for (DWORD nl = 0; nl < numLen; nl++)
																																privKeyOctetLen = (privKeyOctetLen << 8) | pkcs8Ptr[2 + nl];
																															privKeyOctetHdrSize = 2 + numLen;
																														}

																														pkcs8Ptr += privKeyOctetHdrSize;

																														fprintf(stderr, "  Private Key OCTET STRING (%d bytes)\n", privKeyOctetLen);

																														// The OCTET STRING contains an ECPrivateKey SEQUENCE
																														// ECPrivateKey ::= SEQUENCE {
																														//   version INTEGER,
																														//   privateKey OCTET STRING,
																														//   parameters [0] EXPLICIT OPTIONAL,
																														//   publicKey [1] EXPLICIT BIT STRING OPTIONAL
																														// }

																														if (pkcs8Ptr[0] == 0x30)
																														{
																															fprintf(stderr, "  ECPrivateKey SEQUENCE found\n");

																															// Skip SEQUENCE header
																															DWORD ecSeqLen = pkcs8Ptr[1];
																															pkcs8Ptr += 2;

																															// Skip version (INTEGER)
																															if (pkcs8Ptr[0] == 0x02)
																															{
																																DWORD ecVerLen = pkcs8Ptr[1];
																																pkcs8Ptr += 2 + ecVerLen;
																															}

																															// THIS IS THE RAW ECC PRIVATE KEY!
																															if (pkcs8Ptr[0] == 0x04)
																															{
																																DWORD rawPrivKeyLen = pkcs8Ptr[1];
																																BYTE* rawPrivKey = pkcs8Ptr + 2;

																																fprintf(stderr, "\n  *** RAW ECC PRIVATE KEY FOUND! ***\n");
																																fprintf(stderr, "  Private Key Length: %d bytes\n", rawPrivKeyLen);
																																fprintf(stderr, "  Private Key (hex): ");
																																for (DWORD rpk = 0; rpk < rawPrivKeyLen; rpk++)
																																	fprintf(stderr, "%02X", rawPrivKey[rpk]);
																																fprintf(stderr, "\n\n");

																																// Save to file
																																HANDLE hRawKeyFile = CreateFile(L"raw_ecc_private_key.bin",
																																	GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
																																	FILE_ATTRIBUTE_NORMAL, NULL);

																																if (hRawKeyFile != INVALID_HANDLE_VALUE)
																																{
																																	DWORD written = 0;
																																	if (WriteFile(hRawKeyFile, rawPrivKey, rawPrivKeyLen, &written, NULL))
																																	{
																																		fprintf(stderr, "Saved raw ECC private key to raw_ecc_private_key.bin\n");
																																	}
																																	CloseHandle(hRawKeyFile);
																																}

																																// Move past the private key to look for optional fields
																																pkcs8Ptr += 2 + rawPrivKeyLen;

																																// ECPrivateKey can have optional fields:
																																// [0] EXPLICIT parameters (curve OID) - we already have this from AlgorithmIdentifier
																																// [1] EXPLICIT publicKey (BIT STRING)

																																// Check for [0] EXPLICIT (parameters) - usually omitted since curve is in AlgorithmIdentifier
																																if (pkcs8Ptr[0] == 0xA0)
																																{
																																	fprintf(stderr, "\n  Found [0] EXPLICIT tag (parameters)\n");

																																	// Skip [0] EXPLICIT header and its contents
																																	DWORD param0Len = pkcs8Ptr[1];
																																	DWORD param0HdrSize = 2;

																																	if (pkcs8Ptr[1] & 0x80)
																																	{
																																		DWORD numLen = pkcs8Ptr[1] & 0x7F;
																																		param0Len = 0;
																																		for (DWORD nl = 0; nl < numLen; nl++)
																																			param0Len = (param0Len << 8) | pkcs8Ptr[2 + nl];
																																		param0HdrSize = 2 + numLen;
																																	}

																																	pkcs8Ptr += param0HdrSize + param0Len;
																																}

																																// Look for [1] EXPLICIT tag containing the public key
																																// Tag 0xA1 = context-specific, constructed, tag number 1
																																if (pkcs8Ptr[0] == 0xA1)
																																{
																																	fprintf(stderr, "\n  *** PUBLIC KEY FOUND! ***\n");
																																	fprintf(stderr, "  Found [1] EXPLICIT tag for public key\n");

																																	// Skip [1] EXPLICIT header
																																	DWORD pubKeyExplicitLen = pkcs8Ptr[1];
																																	pkcs8Ptr += 2;

																																	// Inside should be a BIT STRING
																																	if (pkcs8Ptr[0] == 0x03)
																																	{
																																		fprintf(stderr, "  Found BIT STRING tag\n");

																																		DWORD bitStringLen = pkcs8Ptr[1];
																																		DWORD bitStringHdrSize = 2;

																																		if (pkcs8Ptr[1] & 0x80)
																																		{
																																			DWORD numLen = pkcs8Ptr[1] & 0x7F;
																																			bitStringLen = 0;
																																			for (DWORD nl = 0; nl < numLen; nl++)
																																				bitStringLen = (bitStringLen << 8) | pkcs8Ptr[2 + nl];
																																			bitStringHdrSize = 2 + numLen;
																																		}

																																		pkcs8Ptr += bitStringHdrSize;

																																		// First byte of BIT STRING is the number of unused bits (usually 0)
																																		BYTE unusedBits = pkcs8Ptr[0];
																																		pkcs8Ptr++;
																																		bitStringLen--; // Subtract the unused bits byte

																																		fprintf(stderr, "  Unused bits: %d\n", unusedBits);
																																		fprintf(stderr, "  Public Key Length: %d bytes\n", bitStringLen);

																																		// The public key is in uncompressed format: 0x04 || X || Y
																																		// First byte should be 0x04 for uncompressed point
																																		if (pkcs8Ptr[0] == 0x04)
																																		{
																																			fprintf(stderr, "  Public Key Format: Uncompressed (0x04)\n");

																																			// Calculate coordinate sizes
																																			DWORD coordSize = (bitStringLen - 1) / 2;
																																			fprintf(stderr, "  Coordinate Size: %d bytes\n", coordSize);

																																			BYTE* pubKeyX = pkcs8Ptr + 1;
																																			BYTE* pubKeyY = pkcs8Ptr + 1 + coordSize;

																																			fprintf(stderr, "\n  Public Key X coordinate (hex): ");
																																			for (DWORD x = 0; x < coordSize; x++)
																																				fprintf(stderr, "%02X", pubKeyX[x]);
																																			fprintf(stderr, "\n");

																																			fprintf(stderr, "  Public Key Y coordinate (hex): ");
																																			for (DWORD y = 0; y < coordSize; y++)
																																				fprintf(stderr, "%02X", pubKeyY[y]);
																																			fprintf(stderr, "\n\n");

																																			// Save full public key (including 0x04 prefix)
																																			HANDLE hPubKeyFile = CreateFile(L"raw_ecc_public_key.bin",
																																				GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
																																				FILE_ATTRIBUTE_NORMAL, NULL);

																																			if (hPubKeyFile != INVALID_HANDLE_VALUE)
																																			{
																																				DWORD written = 0;
																																				if (WriteFile(hPubKeyFile, pkcs8Ptr, bitStringLen, &written, NULL))
																																				{
																																					fprintf(stderr, " Saved raw ECC public key to raw_ecc_public_key.bin\n");
																																				}
																																				CloseHandle(hPubKeyFile);
																																			}
																																		}
																																		else
																																		{
																																			fprintf(stderr, "  Public Key Format: 0x%02X (compressed or other format)\n", pkcs8Ptr[0]);
																																			fprintf(stderr, "  Full Public Key (hex): ");
																																			for (DWORD pk = 0; pk < bitStringLen; pk++)
																																				fprintf(stderr, "%02X", pkcs8Ptr[pk]);
																																			fprintf(stderr, "\n");
																																		}
																																	}
																																}
																																else
																																{
																																	fprintf(stderr, "\n  Public key not found in ECPrivateKey structure (optional field)\n");
																																	fprintf(stderr, "  Next tag: 0x%02X (expected 0xA1 for public key)\n", pkcs8Ptr[0]);
																																}
																															}
																														}
																													}
																												}
																											}
																											delete[] decryptedData;
																										}

																										BCryptDestroyKey(hKey);
																									}
																								}

																								BCryptCloseAlgorithmProvider(hAesAlg, 0);
																							}
																						}

																						BCryptCloseAlgorithmProvider(hAlg, 0);
																					}

																					delete[] utf8Password;
																				}
																			}

																		}
																	}
																}
															}
														}
													}
												}
											}

											LocalFree(pEncPrivKeyInfo);
										}
									}
									else
									{
										fprintf(stderr, "  Failed to decode EncryptedPrivateKeyInfo. Error: 0x%08X\n", GetLastError());
									}
								}
							}
							// Check if it's a certificate bag (1.2.840.113549.1.12.10.1.3)
							else if (strcmp(*pszOid, "1.2.840.113549.1.12.10.1.3") == 0)
							{
								fprintf(stderr, "  Type: Certificate Bag\n");

								bp += 2 + oidLen;

								// Next should be [0] EXPLICIT tag (context-specific, constructed)
								if (bp[0] == 0xA0) // [0] EXPLICIT
								{
									// Skip [0] tag and length
									DWORD explicitHdrSize = 2;
									if (bp[1] & 0x80)
									{
										DWORD lenBytes = bp[1] & 0x7F;
										explicitHdrSize = 2 + lenBytes;
									}
									bp += explicitHdrSize;

									// Inside [0] should be another SEQUENCE (CertBag)
									if (bp[0] == 0x30)
									{
										// Skip SEQUENCE header
										DWORD cbHdrSize = 2;
										if (bp[1] & 0x80)
										{
											DWORD lenBytes = bp[1] & 0x7F;
											cbHdrSize = 2 + lenBytes;
										}
										bp += cbHdrSize;

										// Parse certId (OID) - should be x509Certificate (1.2.840.113549.1.9.22.1)
										if (bp[0] == 0x06)
										{
											DWORD certIdLen = bp[1];
											bp += 2 + certIdLen;

											// Next is [0] EXPLICIT containing the certificate data
											// LINE 518: Remove the check for bp[0] == 0xA0
											// The certificate data may be directly here in various formats

											DWORD remainingBytes = (DWORD)(bagData + bagLen - bp);
											fprintf(stderr, "  Certificate data tag: 0x%02X\n", bp[0]);
											fprintf(stderr, "  Remaining bytes: %d\n", remainingBytes);

											// Handle [0] EXPLICIT wrapper if present
											if (bp[0] == 0xA0)
											{
												DWORD certExplicitHdrSize = 2;
												if (bp[1] & 0x80)
												{
													DWORD lenBytes = bp[1] & 0x7F;
													certExplicitHdrSize = 2 + lenBytes;
												}
												bp += certExplicitHdrSize;
												remainingBytes = (DWORD)(bagData + bagLen - bp);
												fprintf(stderr, "  After [0] EXPLICIT, tag: 0x%02X\n", bp[0]);
											}

											// Now try to decode the certificate regardless of wrapper
											PCCERT_CONTEXT pCert = CertCreateCertificateContext(
												X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
												bp,
												remainingBytes
											);

											if (pCert)
											{
												fprintf(stderr, "Successfully decoded certificate!\n");

												DWORD subjectLen = CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
													0, NULL, NULL, 0);
												char* subject = new char[subjectLen];
												CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
													0, NULL, subject, subjectLen);

												fprintf(stderr, "  Certificate Subject: %s\n", subject);

												DWORD issuerLen = CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
													CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
												char* issuer = new char[issuerLen];
												CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
													CERT_NAME_ISSUER_FLAG, NULL, issuer, issuerLen);

												fprintf(stderr, "  Certificate Issuer: %s\n", issuer);

												fprintf(stderr, "  Serial Number: ");
												for (DWORD sn = pCert->pCertInfo->SerialNumber.cbData; sn > 0; sn--)
												{
													fprintf(stderr, "%02X", pCert->pCertInfo->SerialNumber.pbData[sn - 1]);
												}
												fprintf(stderr, "\n");

												delete[] subject;
												delete[] issuer;
												CertFreeCertificateContext(pCert);
											}
											else
											{
												fprintf(stderr, "  Failed to decode certificate. Error: 0x%08X\n", GetLastError());
												fprintf(stderr, "  First 32 bytes:\n  ");
												for (DWORD d = 0; d < 32 && d < remainingBytes; d++)
												{
													fprintf(stderr, "%02X ", bp[d]);
													if ((d + 1) % 16 == 0) fprintf(stderr, "\n  ");
												}
												fprintf(stderr, "\n");
											}
										}
									}
								}
							}
						
							LocalFree(pszOid);
						}
					}
				}
			}

			LocalFree(pSafeBags);
			LocalFree(pPlainData);
		}
		LocalFree(pSafeContent);
	}

	// Cleanup
	LocalFree(pAuthSafe);
	LocalFree(pDataBlob);
	LocalFree(pAuthSafeContent);
	delete[] wideFileName;
	delete[] password;
	delete[] fileData;
	CloseHandle(hFile);
	return 0;
}

