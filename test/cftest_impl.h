#pragma once

#include <windows.h>
#include <cfapi.h>

namespace cftest {
	constexpr wchar_t dummy_data[] = L"Hello, world!";

	void on_fetch_data(
		const ::CF_CALLBACK_INFO* info,
		const ::CF_CALLBACK_PARAMETERS* parameters
	);
}