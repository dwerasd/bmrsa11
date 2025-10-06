// bmrsa.cpp : Defines the entry point for the console application.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include "bignum.h"


#pragma warning(disable:4996) // Disable deprecation warnings for fopen, etc.

//#define MAXPRIMECOUNT 1000
inline constexpr int MAXPRIMECOUNT = 1000; // Maximum number of small primes to generate

unsigned int nSmallPrimes[MAXPRIMECOUNT][2];
unsigned int nPrimeCount = 0;

void MakeSmallPrimes()
{
	unsigned int n;
	unsigned int j;

	nPrimeCount = 3;
	nSmallPrimes[0][0] = 2;
	nSmallPrimes[1][0] = 3;
	nSmallPrimes[2][0] = 5;
	nSmallPrimes[0][1] = 4;
	nSmallPrimes[1][1] = 9;
	nSmallPrimes[2][1] = 25;

	for (n = 7; nPrimeCount < MAXPRIMECOUNT; n += 2)
	{
		for (j = 0; nSmallPrimes[j][1] < n; j++)
		{
			if (j >= nPrimeCount)
			{
				puts("error");
				return;
			}
			if (n % nSmallPrimes[j][0] == 0)
			{
				break;
			}
		}
		if (nSmallPrimes[j][1] > n)
		{
			nSmallPrimes[nPrimeCount][0] = n;
			nSmallPrimes[nPrimeCount++][1] = n * n;
		}
	}
}

CBigNum GenerateBigRandomNumber(unsigned short nBytes)
{
	CBigNum Result = 0U;
	int i;
	clock_t ctStart;
	unsigned long ctr = 0;
	clock_t ctInterval = CLOCKS_PER_SEC / 50 + 1;

	puts("Generating random number:");

	for (i = 0; i < nBytes * 2; ++i)
	{
		ctStart = clock();
		while (clock() - ctStart < ctInterval)
			ctr++;

		ctr = (ctr % 33) & 0xF;
		printf("%X", ctr);
		Result <<= 4U;
		Result |= ctr;
	}
	putchar('\n');
	return Result;
}

CBigNum FindABigPrime(unsigned short nBytes)
{
	CBigNum nBig, nBig2;
	DWORD j;
	//nBig = "294409"; // Carmichael number
	//nBig = "63973"; // Carmichael number
	DWORD nTestCount = 0;
	DWORD nLehmanCount = 0;
	clock_t ctStartTime = clock();
	DWORD nOffset = 0;

	bool bPrime = false;

	for (nBig = GenerateBigRandomNumber(nBytes) | 1U; !bPrime; nBig += 2U, nOffset += 2)
	{
		nTestCount++;
		puts("Testing for prime:");
		if (nOffset == 0)
		{
			puts(nBig);
		}
		else
		{
			printf("+%d\n", nOffset);
		}

		for (j = 0; j < nPrimeCount; j++)
		{
			if (nBig <= nSmallPrimes[j][0])
				break;

			if (nBig % nSmallPrimes[j][0] == 0)
			{
				printf("It's evenly divisible by %d\n", nSmallPrimes[j][0]);
				break;
			}
		}

		if ((j < nPrimeCount) && (nBig > nSmallPrimes[j][0]))
			continue;

		puts("No small prime factors; trying Lehman method");

		nLehmanCount++;

		nBig2 = (nBig - 1U) / 2U;

		DWORD arnLehmanPrimes[] = { 89, 5179, 25981, 25439, 25013, 25667, 27397 }; // some random prime numbers
		CBigNum LehmanResults[sizeof(arnLehmanPrimes) / sizeof(arnLehmanPrimes[0])];

		nBig2 = nBig - 1U;

		bPrime = true;
		for (j = 0; j < sizeof(arnLehmanPrimes) / sizeof(arnLehmanPrimes[0]); j++)
		{
			LehmanResults[j] = CBigNum(arnLehmanPrimes[j]).PowMod(nBig2, nBig, CLOCKS_PER_SEC);
			if (LehmanResults[j] == nBig2)
			{
				printf("Lehman result %d suggests prime (-1)\n", j);
			}
			else if (LehmanResults[j] == 1U)
			{
				printf("Lehman result %d suggests prime (1)\n", j);
			}
			else
			{
				printf("Lehman result %d indicates composite\n", j);
				bPrime = false;
				break;
			}
		}

		if (bPrime)
		{
			puts(nBig);
			puts("Appears prime");
			break;
		}
	}
	printf("Tested %d numbers before finding a prime. Resorted to Lehman method %d times.\n", nTestCount, nLehmanCount);
	printf("Process took %6.1f seconds.\n", (clock() - ctStartTime) / (float)(CLOCKS_PER_SEC));

	return nBig;
}

void GenKeyPair(CBigNum& PublicMod, CBigNum& PublicKey, CBigNum& PrivateKey, CBigNum& P, CBigNum& Q, unsigned int nByteCount = 32)
{
	const unsigned short nByteCount_ = static_cast<unsigned short>(nByteCount);
	if (0U == (P | Q))
	{
		P = FindABigPrime(nByteCount_);
		Q = FindABigPrime(nByteCount_);
		PublicKey = GenerateBigRandomNumber(nByteCount_) | 1U;
	}
	else {
		PublicKey |= 1U;
	}
	PrivateKey = (P - 1U) * (Q - 1U);
	while (PublicKey > PrivateKey)
		PublicKey = GenerateBigRandomNumber(nByteCount_ - 1) | 1U;
	while (CBigNum::gcd(PublicKey, PrivateKey) != 1U)
		PublicKey += 2;
	PrivateKey = PublicKey.Inverse(PrivateKey);

	PublicMod = P * Q;
}

int main(int argc, char* argv[])
{

	bool bAbort = false;
	unsigned short nBytes = 0; // Key byte-length
	int nCommand = 0;   // 1 = Generate key
	// 2 = Transform input with public key
	// 3 = Transform input with private key
	// 4 = Convert input to another text format
	// 5 = Regenerate private key
	int nMode = 0;      // 0 = Expect switch
	// 1 = Expect key byte-length
	// 2 = Expect key file name
	char szKeyFile[512]{};
	int nTextModeI = 3; // Encrypted Text Mode  0 = Decimal, 1 = Hex, 2 = Printable text, 3=base64
	int nTextModeO = 3; // Decrypted Text Mode  0 = Decimal, 1 = Hex, 2 = Printable text, 3=base64
	int nTextModeK = 3; // Key text mode  0 = Decimal, 1 = Hex, 2 = Printable text, 3 = base64
	//unsigned int nWid=5;

	szKeyFile[0] = '\0';

	if (argc < 2)
	{
		bAbort = true;
	}
	else
	{
		int nArg;

		for (nArg = 1; nArg < argc; nArg++)
		{
			switch (argv[nArg][0])
			{
			case '-':
			case '/':
				switch (argv[nArg][1])
				{
				case 'g':
				case 'G': // Generate key of length <arg>
					nCommand = 1;
					if (argv[nArg][2])
					{
						nBytes = static_cast<unsigned short>(atoi(argv[nArg] + 2));
						nCommand = 1;
					}
					else
						nMode = 1;
					break;
				case 'f':
				case 'F': // key filename
					if (argv[nArg][2])
						strcpy(szKeyFile, argv[nArg] + 2);
					else
						nMode = 2;
					break;
				case 'p':
				case 'P':
					switch (argv[nArg][2])
					{
					case 'u': // Transform through [Pu]blic key
					case 'U':
						nCommand = 2;
						break;
					case 'r': // Transform through [Pr]ivate key
					case 'R':
						nCommand = 3;
						break;
					}
					break;
				case 'c':
				case 'C':
					nCommand = 4;
					break;
				case 'r':
				case 'R':
					nCommand = 5;
					break;
				case 'm':
				case 'M': // Mode switch
					switch (argv[nArg][2])
					{
					case 'i':
					case 'I':
						switch (argv[nArg][3])
						{
						case 'd':
						case 'D':
							nTextModeI = 0;
							break;
						case 'h':
						case 'H':
							nTextModeI = 1;
							break;
						case 't':
						case 'T':
							nTextModeI = 2;
							break;
						case '6':
							nTextModeI = 3;
							break;
						}
						break;
					case 'k':
					case 'K':
						switch (argv[nArg][3])
						{
						case 'd':
						case 'D':
							nTextModeK = 0;
							break;
						case 'h':
						case 'H':
							nTextModeK = 1;
							break;
						case 't':
						case 'T':
							nTextModeK = 2;
							break;
						case '6':
							nTextModeK = 3;
							break;
						}
						break;
					case 'o':
					case 'O':
					case '0':
						switch (argv[nArg][3])
						{
						case 'd':
						case 'D':
							nTextModeO = 0;
							break;
						case 'h':
						case 'H':
							nTextModeO = 1;
							break;
						case 't':
						case 'T':
							nTextModeO = 2;
							break;
						case '6':
							nTextModeO = 3;
							break;
						}
						break;
					}
					break;
				default:
					bAbort = true;
					break;
				}
				break;
			default:
				switch (nMode)
				{
				case 1:
					nBytes = static_cast<unsigned short>(atoi(argv[nArg]));
					nMode = 0;
					break;
				case 2:
					strcpy(szKeyFile, argv[nArg]);
					nMode = 0;
					break;
				default:
					bAbort = true;
					break;
				}
			}
		}
	}

	if (nCommand == 0)
	{
		bAbort = true;
	}

	if (((nCommand == 2) || (nCommand == 3) || (nCommand == 5)) && (szKeyFile[0] == '\0'))
	{
		puts("Key file name required.");
		bAbort = true;
	}

	if (bAbort)
	{
		puts("RSA Encryption, Decryption, Signing and Key Generation Tool\nWritten by Benjamin Marty (BlueMonkMN@email.com)\n"
			"Syntax 1 (generate a key file):\n"
			"   bmrsa [<mode switches>] -g [<byte count>] [-f <key file>]\n"
			"Syntax 2 (tranform text or regenerate private key):\n"
			"   bmrsa [<mode switches>] -f <key file> <command>\n"
			"Syntax 3 (convert text):\n"
			"   bmrsa [<mode switches>] -c\n"
			" <mode switches>: -m<text spec><text mode>\n"
			"     <text spec>: k|i|o\n"
			"                  where k = text of keys in <key file>\n"
			"                        i = text in input stream\n"
			"                        o = text in output stream\n"
			"     <text mode>: d|h|t|6\n"
			"                  where d = decimal\n"
			"                        h = hexadecimal\n"
			"                        t = bytes as printable text (careful here!)\n"
			"              (default) 6 = base64 encoding (no line breaks)\n"
			"     Printable text mode replaces non-printable characters with\n"
			"     periods, so it should only be used on data that is expected\n"
			"     to be printable, and definitely not on a key, which would\n"
			"     almost certainly be corrupted as plain text.\n"
			" <byte count>   : (A decimal number from 4 to 128)\n"
			"                  The byte count determines the number of bytes\n"
			"                  in each prime number that compose the public mod.\n"
			"                  A value of 8 will generate 2 64-bit primes and\n"
			"                  result in a 128-bit public mod and private key.\n"
			"                  (default=32 which gives 512-bit mod)\n"
			" <command>      : -pu[blic] | -pr[ivate] | -r[egen]\n"
			"                  -pu: Transforms the input stream using the\n"
			"                       specified input text mode and the public key\n"
			"                       in the key file, then outputs it to the\n"
			"                       output stream according to the output mode\n"
			"                       (for encrypting or verifying signature).\n"
			"                  -pr: Similarly transforms the input, but using the\n"
			"                       private key (for decrypting or signing).\n"
			"                  -r : You can change the public key in the key file\n"
			"                       and use this command to generate a new\n"
			"                       private key corresponding to that public key.\n"
			"                       This command requires that the key file\n"
			"                       contain the \"private p\" and \"private q\"\n"
			"                       values.  If the specified public key is\n"
			"                       invalid, it will be incremented until valid.\n"
			"                       The public key should be significantly less\n"
			"                       than the mod, but greater than 2.\n"
			" -c : Only convert based on input and output modes.\n"
			"      No key is used to transform the actual values.\n"
			"Examples:\n"
			"  Generate a key file \"mykeys.txt\" containing 256-bit keys in hex format\n"
			"    bmrsa -mkh -g 16 -f MyKeys.txt\n"
			"  Encrypt the text file \"Readme.txt\" using the public key in MyKeys.txt\n"
			"  and output the results to \"Readme.enc\" in hex format:\n"
			"    bmrsa -mkh -mit -moh -pu -f MyKeys.txt <Readme.txt >Readme.enc\n"
			"  Decrypt the text file \"Readme.enc\" using the private key in MyKeys.txt\n"
			"  and output the results to the display:\n"
			"    bmrsa -mkh -mih -mot -pr -f MyKeys.txt <Readme.enc\n"
			"  \"Sign\" the text file \"Readme.txt\" using the private key in MyKeys.txt\n"
			"  and output the binary signed data to \"Readme.sgn\":\n"
			"    bmrsa -mkh -mit -pr -f MyKeys.txt <Readme.txt >Readme.sgn\n"
			"  Verify the signed file \"Readme.sgn\" using the public key in MyKeys.txt\n"
			"  and output the verified plain text to the display:\n"
			"    bmrsa -mkh -mot -pu -f MyKeys.txt <Readme.sgn\n"
			"  Convert this help text to a series of hex numbers and then back to plain\n"
			"  text output to the display ...trust me :):\n"
			"    bmrsa | bmrsa -mit -moh -c | bmrsa -mih -mot -c\n"
			"Notes:\n"
			"  1. Key generation can be slow for large keys.  Be prepared to wait around\n"
			"     10+ minutes for a pair of 128-byte primes.  Transforming text using the\n"
			"     resulting 2048-bit mod can be quite slow as well.\n"
			"  2. Values larger than 128 for byte count will work, but are not\n"
			"     recommended due to performance issues.\n"
			"  3. Each line of input, no matter what format, must be 600 characters max.\n"
			"  4. Each line of input when using a non-text mode must represent a value\n"
			"     no larger than the public mod value in the key file.\n"
			"  5. The private key and P and Q values may be removed from the key file\n"
			"     if you are only transforming based on a public key. (P and Q are only\n"
			"     needed for re-generating new public and private keys on the same mod.\n"
			"     They should be kept as secret as the private key.)");
		return 0;
	}

	FILE* pFile = NULL;
	CBigNum PubMod, PubKey, PriKey, PriP, PriQ;

	if ((nCommand == 2) || (nCommand == 3) || (nCommand == 5))
	{
		unsigned int nFileSize;
		pFile = fopen(szKeyFile, "rt");
		if (NULL == pFile)
		{
			printf("Cannot open key file %s for reading.\n", szKeyFile);
			return -1;
		}

		fseek(pFile, 0, SEEK_END);
		nFileSize = ftell(pFile);
		rewind(pFile);
		if (nFileSize > 50000)
		{
			puts("Key file too big.");
			fclose(pFile);
			return -1;
		}

		char* szFileData = new char[nFileSize + 1];

		unsigned int bytesRead = static_cast<unsigned int>(fread(szFileData, sizeof(szFileData[0]), nFileSize, pFile));
		fclose(pFile);
		nFileSize = bytesRead;

		szFileData[nFileSize] = '\0';

		char* pStartMod, * pStartPubKey, * pStartPriKey, * pStartPriP, * pStartPriQ,
			* pEnd1 = NULL, * pEnd2 = NULL, * pEnd3 = NULL, * pEnd4 = NULL, * pEnd5 = NULL;

		pStartMod = strstr(szFileData, "public mod=");
		if (!pStartMod)
		{
			delete szFileData;
			puts("Public mod not found");
			return -1;
		}
		for (pStartMod = pStartMod + 11; *pStartMod; pStartMod++)
			if (!isspace(*pStartMod))
				break;
		for (pEnd1 = pStartMod; *pEnd1; pEnd1++)
			if (isspace(*pEnd1))
				break;

		pStartPubKey = strstr(szFileData, "public key=");
		if (pStartPubKey)
		{
			for (pStartPubKey = pStartPubKey + 11; *pStartPubKey; pStartPubKey++)
				if (!isspace(*pStartPubKey))
					break;
			for (pEnd2 = pStartPubKey; *pEnd2; pEnd2++)
				if (isspace(*pEnd2))
					break;
		}

		pStartPriKey = strstr(szFileData, "private key=");
		if (pStartPriKey)
		{
			for (pStartPriKey = pStartPriKey + 12; *pStartPriKey; pStartPriKey++)
				if (!isspace(*pStartPriKey))
					break;
			for (pEnd3 = pStartPriKey; *pEnd3; pEnd3++)
				if (isspace(*pEnd3))
					break;
		}

		pStartPriP = strstr(szFileData, "private p=");
		if (pStartPriP)
		{
			for (pStartPriP = pStartPriP + 10; *pStartPriP; pStartPriP++)
				if (!isspace(*pStartPriP))
					break;
			for (pEnd4 = pStartPriP; *pEnd4; pEnd4++)
				if (isspace(*pEnd4))
					break;
		}

		pStartPriQ = strstr(szFileData, "private q=");
		if (pStartPriQ)
		{
			for (pStartPriQ = pStartPriQ + 10; *pStartPriQ; pStartPriQ++)
				if (!isspace(*pStartPriQ))
					break;
			for (pEnd5 = pStartPriQ; *pEnd5; pEnd5++)
				if (isspace(*pEnd5))
					break;
		}

		*pEnd1 = '\0';
		if (pEnd2) *pEnd2 = '\0';
		if (pEnd3) *pEnd3 = '\0';
		if (pEnd4) *pEnd4 = '\0';
		if (pEnd5) *pEnd5 = '\0';

		switch (nTextModeK)
		{
		case 0:
			PubMod = pStartMod;
			if (pStartPubKey)
				PubKey = pStartPubKey;
			if (pStartPriKey)
				PriKey = pStartPriKey;
			if (pStartPriP)
				PriP = pStartPriP;
			if (pStartPriQ)
				PriQ = pStartPriQ;
			break;
		case 1:
			PubMod = CBigNum::FromHexString(pStartMod);
			if (pStartPubKey)
				PubKey = CBigNum::FromHexString(pStartPubKey);
			if (pStartPriKey)
				PriKey = CBigNum::FromHexString(pStartPriKey);
			if (pStartPriP)
				PriP = CBigNum::FromHexString(pStartPriP);
			if (pStartPriQ)
				PriQ = CBigNum::FromHexString(pStartPriQ);
			break;
		case 2:
			PubMod = CBigNum::FromByteString(pStartMod);
			if (pStartPubKey)
				PubKey = CBigNum::FromByteString(pStartPubKey);
			if (pStartPriKey)
				PriKey = CBigNum::FromByteString(pStartPriKey);
			if (pStartPriP)
				PriP = CBigNum::FromByteString(pStartPriP);
			if (pStartPriQ)
				PriQ = CBigNum::FromByteString(pStartPriQ);
			break;
		case 3:
			PubMod = CBigNum::FromBase64String(pStartMod);
			if (pStartPubKey)
				PubKey = CBigNum::FromBase64String(pStartPubKey);
			if (pStartPriKey)
				PriKey = CBigNum::FromBase64String(pStartPriKey);
			if (pStartPriP)
				PriP = CBigNum::FromBase64String(pStartPriP);
			if (pStartPriQ)
				PriQ = CBigNum::FromBase64String(pStartPriQ);
			break;
		}

		delete szFileData;

		if ((nCommand == 3) && (pStartPriKey == NULL))
		{
			puts("Private key not found in key file.");
			return -1;
		}

		if (((nCommand == 2) || (nCommand == 5)) && (pStartPubKey == NULL))
		{
			puts("Public key not found in key file.");
			return -1;
		}

		if ((nCommand == 5) && ((pStartPriP == NULL) || (pStartPriQ == NULL)))
		{
			puts("Private P and/or Private Q not found in key file.");
			return -1;
		}
	}

	if ((nCommand > 1) && (nCommand < 5))
	{
		char szLineBuf[601];
		CBigNum Transform;
		CBigNumString strTransform;
		size_t cbReadCount;
		unsigned int nMaxByteCount;
		if (nCommand < 4)
		{
			nMaxByteCount = (PubMod.log2() - 1) / 8U;
			if (nMaxByteCount >= sizeof(szLineBuf))
				nMaxByteCount = sizeof(szLineBuf) - 1;
		}
		else
		{
			if (nTextModeI == 2)
				nMaxByteCount = 80;
			else
				nMaxByteCount = sizeof(szLineBuf) - 1;
		}

		while (1)
		{
			if (nTextModeI == 2)
			{
				if (feof(stdin))
					break;
				cbReadCount = fread(szLineBuf, 1, nMaxByteCount, stdin);
				if (cbReadCount == 0)
					break;
				szLineBuf[cbReadCount] = '\0';
			}
			else
			{
				if (!fgets(szLineBuf, sizeof(szLineBuf), stdin))
					break;
				if (!feof(stdin) && (!isspace(szLineBuf[strlen(szLineBuf) - 1])))
				{
					fputs("Entry too long.\n", stderr);
					while (1)
					{
						const char ch = static_cast<char>(getchar());
						if ((ch == EOF) || (ch == '\n'))
							break;
					}
					continue;
				}
				while (isspace(szLineBuf[strlen(szLineBuf) - 1]))
					szLineBuf[strlen(szLineBuf) - 1] = '\0';
			}
			switch (nTextModeI)
			{
			case 0:
				Transform = szLineBuf;
				break;
			case 1:
				Transform = CBigNum::FromHexString(szLineBuf);
				break;
			case 2:
				Transform = CBigNum::FromByteString(szLineBuf);
				break;
			case 3:
				Transform = CBigNum::FromBase64String(szLineBuf);
				break;
			}
			if (nCommand < 4)
			{
				if (Transform > PubMod)
				{
					fputs("Too much text in a single entry.\n", stderr);
					continue;
				}
				else if (nCommand == 2)
				{
					Transform = Transform.PowMod(PubKey, PubMod);
				}
				else if (nCommand == 3)
				{
					Transform = Transform.PowMod(PriKey, PubMod);
				}
			}

			switch (nTextModeO)
			{
			case 0:
				strTransform = Transform;
				break;
			case 1:
				strTransform = Transform.ToHexString();
				break;
			case 2:
				strTransform = Transform.ToByteString();
				break;
			case 3:
				strTransform = Transform.ToBase64String();
				break;
			}

			if (nTextModeO == 2)
				printf("%s", (const char*)strTransform);
			else
				puts(strTransform);
		}
	}
	else
	{
		CBigNumString strMod, strPubKey, strPriKey, strP, strQ;

		MakeSmallPrimes();

		if (nCommand == 1)
		{
			PriP = 0U;
			PriQ = 0U;
		}

		if (nBytes > 0)
			GenKeyPair(PubMod, PubKey, PriKey, PriP, PriQ, nBytes);
		else
			GenKeyPair(PubMod, PubKey, PriKey, PriP, PriQ);

		if (szKeyFile[0])
		{
			pFile = fopen(szKeyFile, "wt");
			if (NULL == pFile)
			{
				printf("Cannot open key file %s for writing.\n", szKeyFile);
				return -1;
			}
		}

		switch (nTextModeK)
		{
		case 0:
			strMod = PubMod;
			strPubKey = PubKey;
			strPriKey = PriKey;
			strP = PriP;
			strQ = PriQ;
			break;
		case 1:
			strMod = PubMod.ToHexString();
			strPubKey = PubKey.ToHexString();
			strPriKey = PriKey.ToHexString();
			strP = PriP.ToHexString();
			strQ = PriQ.ToHexString();
			break;
		case 2:
			strMod = PubMod.ToByteString();
			strPubKey = PubKey.ToByteString();
			strPriKey = PriKey.ToByteString();
			strP = PriP.ToByteString();
			strQ = PriQ.ToByteString();
			break;
		case 3:
			strMod = PubMod.ToBase64String();
			strPubKey = PubKey.ToBase64String();
			strPriKey = PriKey.ToBase64String();
			strP = PriP.ToBase64String();
			strQ = PriQ.ToBase64String();
			break;
		}


		fprintf(pFile == NULL ? stdout : pFile,
			"public mod=%s\npublic key=%s\nprivate key=%s\nprivate p=%s\nprivate q=%s",
			(const char*)strMod,
			(const char*)strPubKey,
			(const char*)strPriKey,
			(const char*)strP,
			(const char*)strQ);

		if (pFile != NULL)
			fclose(pFile);
	}

	return 0;
}

// ===========================================
// bmrsa.exe - RSA 암호화/복호화 도구 사용법
// ===========================================

// ----- 기본 문법 -----
// 1. 키 생성: bmrsa [모드스위치] -g [바이트수] [-f 키파일명]
// 2. 암호화/복호화: bmrsa [모드스위치] -f 키파일명 <명령어>  
// 3. 텍스트 변환: bmrsa [모드스위치] -c

// ----- 모드 스위치 (-m) -----
// -m<텍스트종류><텍스트모드>
// 텍스트종류: k=키파일 | i=입력스트림 | o=출력스트림
// 텍스트모드: d=10진수 | h=16진수 | t=텍스트 | 6=base64(기본값)

// ----- 명령어 -----
// -pu : 공개키로 변환 (암호화/서명검증)
// -pr : 개인키로 변환 (복호화/서명)
// -r  : 개인키 재생성
// -c  : 텍스트 변환만 (암호화 없음)

// ----- 옵션 -----
// -g[바이트수] : 키 생성 (4~128, 기본값=32바이트=512비트)
// -f파일명     : 키 파일명 지정

// ===========================================
// 사용 예제
// ===========================================

// 1. 키 생성 (256비트, 16진수 형태)
//bmrsa -mkh -g 16 -f MyKeys.txt

// 2. 파일 암호화 (텍스트→16진수)
//bmrsa -mkh -mit -moh -pu -f MyKeys.txt <Readme.txt >Readme.enc

// 3. 파일 복호화 (16진수→텍스트)
//bmrsa -mkh - mih -mot -pr -f MyKeys.txt < Readme.enc

// 4. 디지털 서명
//bmrsa -mkh -mit -pr -f MyKeys.txt <Readme.txt >Readme.sgn

// 5. 서명 검증
//bmrsa -mkh -mot -pu -f MyKeys.txt < Readme.sgn

// 6. 텍스트 변환 체인 테스트
//bmrsa | bmrsa -mit -moh -c | bmrsa - mih -mot -c

// ===========================================
// 빠른 시작 (기본 512비트 키)
// ===========================================

// 키 생성
//bmrsa -g 32 -f mykey.txt

// 텍스트 암호화 (base64)
//echo "Hello World" | bmrsa -mit - m06 -pu -f mykey.txt

// 복호화 (위 출력을 입력으로)
//echo "암호화된문자열" | bmrsa - mi6 -mot -pr -f mykey.txt

// ===========================================
// 키 파일 형식
// ===========================================
// public mod=<공개모듈러스>
// public key=<공개키>  
// private key=<개인키>
// private p=<소수 p>
// private q=<소수 q>

// ===========================================
// 주의사항
// ===========================================
// - 키 크기가 클수록 생성/변환 시간 오래 걸림 (128바이트=10분+)
// - 각 줄 최대 600자 제한
// - 입력값은 공개모듈러스보다 작아야 함
// - 개인키와 P,Q값은 보안 유지 필수
// - 교육/테스트용, 운영환경에서는 검증된 라이브러리 사용 권장


// 키 생성
//bmrsa -g 32 -f mykey.txt

// 암호화  
//bmrsa -mit - m06 -pu -f mykey.txt

// 복호화
//bmrsa - mi6 -mot -pr -f mykey.txt

// 파일 암호화
//bmrsa -mkh -mit -moh -pu -f mykey.txt <input.txt >output.enc

// 파일 복호화  
//bmrsa -mkh - mih -mot -pr -f mykey.txt < output.enc
