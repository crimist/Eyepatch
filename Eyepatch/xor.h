#pragma once
#include "includes.h"
#include <string.h>

// tune
#define XOR_SEED (0xDEADA55ull)

#ifndef XOR_SEED
#define XOR_SEED	((__TIME__[7] - '0') * 1ull		+ (__TIME__[6] - '0') * 10ull  + \
					(__TIME__[4] - '0') * 60ull		+ (__TIME__[3] - '0') * 600ull + \
					(__TIME__[1] - '0') * 3600ull	+ (__TIME__[0] - '0') * 36000ull)
#endif

namespace crypt {
	// mostly pasted: https://stackoverflow.com/a/56847099/6389542
	constexpr unsigned long long linear_congruent_generator(unsigned rounds = 10) {
		return 1013904223ull + (1664525ull * ((rounds > 0) ? linear_congruent_generator(rounds - 1) : (XOR_SEED))) % 0xFFFFFFFF;
	}
	constexpr auto random(int min, int max) {
		return (min + (linear_congruent_generator() % (max - min + 1)));
	}
	constexpr const auto xorkey = random(0, 0xFF);

	template<typename Char>
	constexpr Char encrypt_character(const Char character, int index) {
		return character ^ (static_cast<Char>(xorkey) + index);
	}

	template <unsigned size, typename Char>
	class XorString {
		const unsigned _nb_chars = (size - 1);
		Char _string[size];

	public:
		inline constexpr XorString(const Char* string) : _string{} {
			for (unsigned i = 0u; i < size; i++)
				_string[i] = encrypt_character<Char>(string[i], i);
		}

		const Char* decrypt() const {
			Char* string = const_cast<Char*>(_string);
			for (unsigned t = 0; t < _nb_chars; t++) {
				string[t] = string[t] ^ (static_cast<Char>(xorkey) + t);
			}
			string[_nb_chars] = '\0';
			return string;
		}
	};

	// non pasted
	template <typename T>
	class XorNum {
		T number;
	public:
		// https://stackoverflow.com/questions/2785612/c-what-does-the-colon-after-a-constructor-mean
		inline constexpr XorNum(const T num) : number{} {
			number = num ^ (static_cast<T>(xorkey));
		}

		const T decrypt() const {
			return this->number ^ (static_cast<T>(xorkey));
		}
	};
}

// bug in intellisense that thinks there's error when there's not: https://github.com/microsoft/vscode-cpptools/issues/2939
#ifdef __INTELLISENSE__
#define xc(string) []{ crypt::XorString<(sizeof(string)/sizeof(char)), char> expr(string); return expr; }().decrypt()
#define xcw(string) []{ crypt::XorString<(sizeof(string)/sizeof(wchar_t)), wchar_t> expr(string); return expr; }().decrypt()
#define xcn(name, string) auto name = crypt::XorString<(sizeof(string) / sizeof(char)), char>(string)
#define xcwn(name, string) auto name = crypt::XorString<(sizeof(string) / sizeof(wchar_t)), wchar_t>(string)
#else
// lambda for in place decryption
#define xc(string)	[]{ constexpr crypt::XorString<(sizeof(string)/sizeof(char)), char> expr(string); return expr; }().decrypt()
#define xcw(string)	[]{ constexpr crypt::XorString<(sizeof(string)/sizeof(wchar_t)), wchar_t> expr(string); return expr; }().decrypt()
// macro for creating XorString class
#define xcn(name, string) constexpr auto name = crypt::XorString<(sizeof(string) / sizeof(char)), char>(string)
#define xcwn(name, string) constexpr auto name = crypt::XorString<(sizeof(string) / sizeof(wchar_t)), wchar_t>(string)
#endif

#if 0 // When the bug in intellisense is fixed use this block
#define xcn(string) crypt::XorString<(sizeof(string) / sizeof(char)), char>(string)
#define xcwn(string) crypt::XorString<(sizeof(string) / sizeof(wchar_t)), wchar_t>(string)
// constexpr auto str = xcn("encrypted string");
// str.decrypt();
#endif

// xor crypt integer
#define xci(num) []{ constexpr crypt::XorNum expr(num); return expr; }().decrypt()
#define xcit(num, type) []{ constexpr crypt::XorNum<type> expr(num); return expr; }().decrypt()

namespace crypt {
	inline void check() {
		DPrint("Crypt seed %X", XOR_SEED);

		// use defines so func is empty on release builds
		#define CRYPT_CHECK_ERROR "xor seed runtime/compiletime mismatch"
		#define CRYPT_CHECK_INT 0x1337FFFF
		#define CRYPT_CHECK_INT64 0x1337FFFFFFFFFFFF
		#define CRYPT_CHECK_STRING "qwertyuiop[]{}\\|\"\';:123%$#@!~"
		#define CRYPT_CHECK_STRING_WIDE L"qwertyuiop[]{}\\|\"\';:123%$#@!~"

		RTL_SOFT_ASSERTMSG(CRYPT_CHECK_ERROR, xci(CRYPT_CHECK_INT) == CRYPT_CHECK_INT);
		RTL_SOFT_ASSERTMSG(CRYPT_CHECK_ERROR, xci(CRYPT_CHECK_INT64) == CRYPT_CHECK_INT64);
		RTL_SOFT_ASSERTMSG(CRYPT_CHECK_ERROR, (strcmp(xc(CRYPT_CHECK_STRING), CRYPT_CHECK_STRING) == 0));
		RTL_SOFT_ASSERTMSG(CRYPT_CHECK_ERROR, (wcscmp(xcw(CRYPT_CHECK_STRING_WIDE), CRYPT_CHECK_STRING_WIDE) == 0));

		DPrint("Crypt check passed");
	}
}
