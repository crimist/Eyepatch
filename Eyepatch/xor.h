#pragma once
#include "includes.h"
#include <string.h>

// tune
//#define XOR_SEED (0xDEADull)

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
	public:
		const unsigned _nb_chars = (size - 1);
		Char _string[size];

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
		inline constexpr XorNum(const T num) : number{} { // todo: understand this
			number = num ^ (static_cast<T>(xorkey));
		}

		const T decrypt() const {
			return this->number ^ (static_cast<T>(xorkey));
		}
	};
}

#define xcnum(num, type) []{ constexpr crypt::XorNum<type> expr(num); return expr; }().decrypt()

#ifdef __INTELLISENSE__ // bug in intellisense that thinks there's error when there's not: https://github.com/microsoft/vscode-cpptools/issues/2939
#define xc(string) (string)
#define xcw(string) (string)
#else
#define xc(string)	[]{ constexpr crypt::XorString<(sizeof(string)/sizeof(char)), char> expr(string); return expr; }().decrypt()
#define xcw(string)	[]{ constexpr crypt::XorString<(sizeof(string)/sizeof(wchar_t)), wchar_t> expr(string); return expr; }().decrypt()
#endif

namespace crypt {
	void check() {
		DPrint("Crypt seed %llu", XOR_SEED);

		// use defines so func is empty on release builds
		#define CRYPT_TEST_NUM 0xDEADA55
		RTL_SOFT_ASSERTMSG("xor seed runtime/compiletime mismatch", xcnum(CRYPT_TEST_NUM, int) == CRYPT_TEST_NUM);

		#define CRYPT_TEST_STRING "qwertyuiop[]{}\|\"\';:123%$#@!~"
		RTL_SOFT_ASSERTMSG("xor seed runtime/compiletime mismatch", (strcmp(xc(CRYPT_TEST_STRING), CRYPT_TEST_STRING) == 0));

		DPrint("Crypt check passed");
	}
}
