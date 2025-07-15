#pragma once

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
	int handshake();

	/* Send a request in JSON format to the TP-Link device
	 *
	 * @returns the decrypted response from the device
	 */
	string sendRequest(std::string request);

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
	int checkConnection();

	void generateLocalSeed();

	/*
	 * Set all the cryptographic parameters based on handshake responses
	 * Handshake 1 and handshake 2 must have both completed successfully for this to work correctly
	 */
	void deriveCryptographicParameters();

	// Returns its success/failure code
	int handshake1();
	int handshake2();

	/*
	 * Uses PKCS7 padding with the block size defined in this class
	 * Last byte of payload is the total padding bytes
	 */
	void padPayload(vector<byte> &payload);
	/*
	 * Unpads according to PKCS7
	 */
	void unpadPayload(vector<byte> &payload);

	/*
	 * Generate the IV used for AES
	 */
	array<byte, 16> deriveAESIv();

	void incrementSequence();

	/* Returns the sequence in INT32 big endian format */
	int32_t readSequenceAsInt32BE();

	void signPayload(vector<byte> &payload);

	/*
	 * Pads and then encrypts
	 */
	void encryptPayload(vector<byte> &payload);
	/*
	 * Decrypts and then unpads
	 */
	void decryptResponse(vector<byte> &payload);

	// Hashing implementations fit for ESP32, feel free to modify to other libraries (eg. openssl)
	array<byte, 20> SHA1(byte *input, size_t length);
	array<byte, 32> SHA256(byte *input, size_t length);
};
