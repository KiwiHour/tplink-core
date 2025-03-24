/*
 * Credientials of your TP-Link account (such as tapo)
 * Used directly for TPLinkCore
 */

#include <string>

using namespace std;

#ifndef CREDENTIALS_H // Check if the symbol is not already defined
#define CREDENTIALS_H // Define the symbol

class Credentials
{
public:
	static string username; // Email or username
	static string password;
};

#endif // CREDENTIALS_H