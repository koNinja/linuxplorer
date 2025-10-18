#include <gtest/gtest.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <shell/filesystem/cloud_provider_registrar.hpp>
#include <shell/filesystem/cloud_filter_placeholder.hpp>
