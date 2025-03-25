#include <array>
#include <vector>
#include <random>
#include <chrono>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include "credentials.h"

// Arduino libraries
#include <HTTPClient.h>
#include <WiFiClient.h>

using namespace std;
typedef uint8_t byte; // For semantic clarity

/*
 * Must have connected to the same network that the TP-Link device is on
 */
class TPLinkCore
{
public:
	// Init attributes
	string deviceIP;		 // Local IPv4 of your device
	int cookieTimeout_s;	 // How long the cookie will last from the handshake (in seconds)
	Credentials credentials; // TP-Link account credentials

	/*  0 Success
	 *  1 Handshake 1 failed
	 *  2 Handshake 2 failed
	 * -1 Network cannot find device using given IP
	 */
	int handshake()
	{
		int connectionStatus = checkConnection();
		if (connectionStatus == EXIT_FAILURE)
			return -1;
		if (handshake1() == EXIT_FAILURE)
			return 1;
		if (handshake2() == EXIT_FAILURE)
			return 2;

		// Once the hands are shaken, derive the cryptographic parameters from what we've been given
		deriveCryptographicParameters();

		return EXIT_SUCCESS;
	}

	/* Send a request in JSON format to the TP-Link device
	 *
	 * @returns the decrypted response from the device
	 */
	string sendRequest(std::string request)
	{
		// Convert request to payload format
		vector<byte> payload(request.begin(), request.end());

		// Prepare payload for HTTP request
		incrementSequence();
		encryptPayload(payload);
		signPayload(payload);

		// Prepare HTTP
		HTTPClient http;
		string url = "http://" + deviceIP + "/app/request?seq=" + to_string(readSequenceAsInt32BE());
		http.begin(url.c_str());
		http.addHeader("Cookie", sessionCookie.c_str());

		// Execute POST request
		int responseCode = http.POST(payload.data(), payload.size());
		size_t responseSize = http.getSize();
		vector<byte> response(responseSize);

		if (responseCode != 200)
		{
			http.end();
			return "eh oh";
		}

		// Extract and decrypt response
		WiFiClient stream = http.getStream();
		stream.readBytes(response.data(), responseSize);
		decryptResponse(response);

		// Convert bytes to string
		return string(response.begin(), response.end());
	}

private:
	// Handshake bytes
	array<byte, 16> localSeed;
	array<byte, 16> remoteSeed;
	array<byte, 32> serverHash;
	array<byte, 32> userHash; // SHA256

	// Cryptographic parameters
	array<byte, 16> key;
	array<byte, 32> iv;
	array<byte, 28> signature;
	array<byte, 4> sequence;

	// PKCS7
	const size_t paddingBlockSize = 16;

	string sessionCookie;

	/*  0 Connected to a network that can talk to the device
	 *  1 Connected network cannot find the device IP
	 */
	int checkConnection()
	{
		HTTPClient http;
		string url = "http://" + deviceIP;
		http.begin(url.c_str());

		int responseCode = http.GET();
		if (responseCode != 200)
		{
			http.end();
			return EXIT_FAILURE;
		}

		return EXIT_SUCCESS;
	}

	void generateLocalSeed()
	{
		array<byte, 16> buffer;

		for (size_t i = 0; i < 16; i++)
		{
			// Technically not 100% secure, but this ain't MI6
			unsigned int seed = chrono::high_resolution_clock::now().time_since_epoch().count();
			srand(seed);
			localSeed[i] = rand() % 256;
		}
	}

	/*
	 * Set all the cryptographic parameters based on handshake responses
	 * Handshake 1 and handshake 2 must have both completed successfully for this to work correctly
	 */
	void deriveCryptographicParameters()
	{
		// Setup beginnings of each cryptographic precursor
		array<byte, 67> signaturePrecursor = {'l', 'd', 'k', 0};
		array<byte, 67> keyPrecursor = {'l', 's', 'k', 0};
		array<byte, 66> ivPrecursor = {'i', 'v', 0};

		// Derive the cryptographic base to be appended to each of the precursors
		array<byte, 64> cryptographicBase;
		std::copy(localSeed.begin(), localSeed.end(), cryptographicBase.begin());
		std::copy(remoteSeed.begin(), remoteSeed.end(), cryptographicBase.begin() + 16);
		std::copy(userHash.begin(), userHash.end(), cryptographicBase.begin() + 32);

		// Append the base to each of the precursors
		std::copy(cryptographicBase.begin(), cryptographicBase.end(), signaturePrecursor.begin() + 3);
		std::copy(cryptographicBase.begin(), cryptographicBase.end(), keyPrecursor.begin() + 3);
		std::copy(cryptographicBase.begin(), cryptographicBase.end(), ivPrecursor.begin() + 2);

		// Hash the precursors to derive each of the cryptographic parameters
		array<byte, 32> temporarySignature = SHA256(signaturePrecursor.data(), 67);
		array<byte, 32> temporaryKey = SHA256(keyPrecursor.data(), 67);
		array<byte, 32> temporaryIv = SHA256(ivPrecursor.data(), 66);

		// Take required bytes from full hash to derive each parameter
		std::copy(temporarySignature.begin(), temporarySignature.begin() + 28, signature.begin()); // First 28 bytes
		std::copy(temporaryKey.begin(), temporaryKey.begin() + 16, key.begin());				   // First 16 bytes
		std::copy(temporaryIv.begin(), temporaryIv.end(), iv.begin());							   // All (32) bytes

		// Derive sequence from the IV
		// Sequence is incremented on each request, and added back onto the IV for AES encryption
		std::copy(iv.begin() + 28, iv.end(), sequence.begin()); // Last 4 bytes of IV
	}

	// Returns its success/failure code
	int handshake1()
	{
		// Setup
		HTTPClient http;
		string url = "http://" + deviceIP + "/app/handshake1";
		const char *desiredHeaderKeys[] = {"Set-Cookie"};

		http.begin(url.c_str());
		http.collectHeaders(desiredHeaderKeys, 1); // Explicitly state that we want the Set-Cookie header

		// Execute POST
		int responseCode = http.POST(localSeed.data(), 16);
		if (responseCode != 200)
		{
			http.end();
			return EXIT_FAILURE;
		}

		// Confirmed 200 code from here, extract response bytes and clean up
		WiFiClient stream = http.getStream();
		array<byte, 48> responseBytes; // Only expecting 48 bytes from the response here
		stream.readBytes(responseBytes.data(), 48);
		http.end();

		// Get the session cookie
		string cookies = http.header("Set-Cookie").c_str();
		sessionCookie = cookies.substr(0, cookies.find(";"));
		cookieTimeout_s = atoi(cookies.substr(cookies.find(";") + 9, cookies.size()).c_str()); // "+9 is for the length of the ;TIMEOUT="

		// Dole out response bytes into correct arrays
		std::copy(responseBytes.begin(), responseBytes.begin() + 16, remoteSeed.begin());
		std::copy(responseBytes.begin() + 16, responseBytes.end(), serverHash.begin());

		return EXIT_SUCCESS;
	}

	int handshake2()
	{
		vector<byte> usernameBytes = vector<byte>(credentials.username.begin(), credentials.username.end());
		vector<byte> passwordBytes = vector<byte>(credentials.password.begin(), credentials.password.end());
		array<byte, 20> usernameHash = SHA1(usernameBytes.data(), usernameBytes.size());
		array<byte, 20> passwordHash = SHA1(passwordBytes.data(), passwordBytes.size());
		array<byte, 40> userHashPrecursor;

		// Concatenate username and password hash into the precursor
		std::copy(usernameHash.begin(), usernameHash.end(), userHashPrecursor.begin());
		std::copy(passwordHash.begin(), passwordHash.end(), userHashPrecursor.begin() + 20);

		// Hash precursor into user hash
		userHash = SHA256(userHashPrecursor.data(), 40);

		// Concatenate local seed, remote seed and user hash into the precursor
		array<byte, 64> handshakeAuthPrecursor;
		std::copy(localSeed.begin(), localSeed.end(), handshakeAuthPrecursor.begin());
		std::copy(remoteSeed.begin(), remoteSeed.end(), handshakeAuthPrecursor.begin() + 16);
		std::copy(userHash.begin(), userHash.end(), handshakeAuthPrecursor.begin() + 32);

		// Generate the auth hash
		array<byte, 32> handshakeAuthHash = SHA256(handshakeAuthPrecursor.data(), 64);

		// Ensure the bytes match with the server hash from handshake 1.
		// If they do, the handshakes were successful and the session cookie has been authenticated
		for (int i = 0; i < 32; i++)
		{
			if (serverHash[i] != handshakeAuthHash[i])
				return EXIT_FAILURE;
		}

		// Generate payload for handshake 2 POST
		array<byte, 64> handshakePayloadPrecursor;
		std::copy(remoteSeed.begin(), remoteSeed.end(), handshakePayloadPrecursor.begin());
		std::copy(localSeed.begin(), localSeed.end(), handshakePayloadPrecursor.begin() + 16);
		std::copy(userHash.begin(), userHash.end(), handshakePayloadPrecursor.begin() + 32);

		// Hash precursor to generate payload
		array<byte, 32> handshakePayload = SHA256(handshakePayloadPrecursor.data(), 64);

		// Send POST request
		HTTPClient http;
		string url = "http://" + deviceIP + "/app/handshake2";

		http.begin(url.c_str());
		http.addHeader("Cookie", sessionCookie.c_str());
		int responseCode = http.POST(handshakePayload.data(), 32);

		// Clean up and return success based on response code
		http.end();

		if (responseCode != 200)
			return EXIT_FAILURE;

		return EXIT_SUCCESS;
	}

	/*
	 * Uses PKCS7 padding with the block size defined in this class
	 * Last byte of payload is the total padding bytes
	 */
	void padPayload(vector<byte> &payload)
	{
		size_t paddingLength = paddingBlockSize - (payload.size() % paddingBlockSize);
		for (int i = 0; i < paddingLength; i++)
		{
			payload.push_back(paddingLength); // Padding length is used as the padding byte
		}
	}

	/*
	 * Unpads according to PKCS7
	 */
	void unpadPayload(vector<byte> &payload)
	{
		size_t paddingLength = payload.back(); // Padding length is the last byte
		for (int i = 0; i < paddingLength; i++)
		{
			payload.pop_back();
		}

		// Remove empty bytes at the end of the payload
		payload.shrink_to_fit();
	}

	/*
	 * Generate the IV used for AES
	 */
	array<byte, 16> deriveAESIv()
	{
		array<byte, 16> AESIv;

		// First 12 bytes of IV and all of sequence are concatenated
		std::copy(iv.begin(), iv.begin() + 12, AESIv.begin());
		std::copy(sequence.begin(), sequence.end(), AESIv.begin() + 12);

		return AESIv;
	}

	void incrementSequence()
	{
		sequence[sequence.size() - 1] += 1;
	}

	/* Returns the sequence in INT32 big endian format */
	int32_t readSequenceAsInt32BE()
	{
		return (static_cast<int32_t>(sequence[0]) << 24) |
			   (static_cast<int32_t>(sequence[1]) << 16) |
			   (static_cast<int32_t>(sequence[2]) << 8) |
			   (static_cast<int32_t>(sequence[3]));
	}

	void signPayload(vector<byte> &payload)
	{
		// Generate precursor
		vector<byte> payloadSignaturePrecursor;
		payloadSignaturePrecursor.resize(32 + payload.size());

		std::copy(signature.begin(), signature.end(), payloadSignaturePrecursor.begin());
		std::copy(sequence.begin(), sequence.end(), payloadSignaturePrecursor.begin() + 28);
		std::copy(payload.begin(), payload.end(), payloadSignaturePrecursor.begin() + 32);

		// Hash precursor to produce the payload's signature
		array<byte, 32> payloadSignature = SHA256(payloadSignaturePrecursor.data(), payloadSignaturePrecursor.size());

		// Sign the payload by prepending the signature to it
		payload.insert(payload.begin(), payloadSignature.begin(), payloadSignature.end());
	}

	/*
	 * Pads and then encrypts
	 */
	void encryptPayload(vector<byte> &payload)
	{
		padPayload(payload);

		mbedtls_aes_context aes;
		mbedtls_aes_init(&aes);
		mbedtls_aes_setkey_enc(&aes, key.data(), 128); // AES-128
		mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, payload.size(), deriveAESIv().data(), payload.data(), payload.data());
		mbedtls_aes_free(&aes);
	}

	/*
	 * Decrypts and then unpads
	 */
	void decryptResponse(vector<byte> &payload)
	{
		// Remove signature (32 bytes) from beginning of payload
		payload.erase(payload.begin(), payload.begin() + 32);

		mbedtls_aes_context aes;
		mbedtls_aes_init(&aes);
		mbedtls_aes_setkey_dec(&aes, key.data(), 128); // AES-128
		mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, payload.size(), deriveAESIv().data(), payload.data(), payload.data());
		mbedtls_aes_free(&aes);

		unpadPayload(payload);
	}

	// Hashing implementations fit for ESP32, feel free to modify to other libraries (eg. openssl)
	array<byte, 20> SHA1(byte *input, size_t length)
	{
		array<byte, 20> output;

		mbedtls_sha1_context ctx;
		mbedtls_sha1_init(&ctx);
		mbedtls_sha1_starts_ret(&ctx);
		mbedtls_sha1_update_ret(&ctx, input, length);
		mbedtls_sha1_finish_ret(&ctx, output.data());
		mbedtls_sha1_free(&ctx);

		return output;
	}

	array<byte, 32> SHA256(byte *input, size_t length)
	{
		array<byte, 32> output;

		mbedtls_sha256_context ctx;
		mbedtls_sha256_init(&ctx);
		mbedtls_sha256_starts_ret(&ctx, 0); // 0 = SHA256
		mbedtls_sha256_update_ret(&ctx, input, length);
		mbedtls_sha256_finish_ret(&ctx, output.data());
		mbedtls_sha256_free(&ctx);

		return output;
	}
};
