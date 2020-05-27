#pragma once

// https://github.com/frankie-11/eft-external/blob/master/EFT%20Kernel/socket-km/server_shared.h

namespace packet {
	enum Type {
		ping,
		walkDrivers,
		hideDriver,
		cleanPiDDB,
		unload,
	};

	struct Ping {
		uint64_t echo;
	};

	struct Packet {
		Type header;
		union {
			Ping ping;
		} data;
	};

}
