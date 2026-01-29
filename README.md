# linuxplorer
**The portable SFTP client integrated with Windows Explorer.**

## Overview
<img width="60%" alt="Screenshot 2026-01-17 155000" src="https://github.com/user-attachments/assets/4713f383-6fdf-460a-ac85-4d722a18c3b3" />

linuxplorer is a personal project that integrates remote Linux files accessed via SFTP into Windows Explorer.  
It leverages the [Windows Cloud Filter API](https://learn.microsoft.com/en-us/windows/win32/api/_cloudapi) to expose a virtual filesystem with on-demand access to remote files.

It aims to provide an experience similar to OneDrive or Dropbox,
but is **not intended to be a production-ready replacement**.
This project is intended for developers who want to browse remote
Linux files from Windows Explorer for personal use.

## Features
- Integration with Windows Explorer
- No installation required
- No admin privileges
- On-demand file access
- Support for file and directory upload
- Propagation of client-side file changes to the server

## Requirements
- Windows 10 1709 or higher

## Notes
- Not as stable as commercial products (e.g. OneDrive, Dropbox)
- Provided as-is, without any warranty
- Use at your own risk

### Conflict handling
linuxplorer does NOT perform conflict detection or resolution.

If the same file is modified both locally and on the remote server,
the last applied change will overwrite the previous one.
Use with caution when accessing files that may be edited concurrently.

### File synchronization behavior
linuxplorer is primarily **client-driven**.

- Local file operations (create, modify, delete, etc) are accepted and
  applied to the remote server immediately.
- Remote-side changes are partially reflected on the client:
  - Metadata updates (timestamps, size)
  - Newly created files and directories

However, **cached file contents are NOT automatically refreshed**.
If a file is modified on the remote server, the user must explicitly
refresh or re-download the file to update the local cache.

## Getting started
Download the prebuilt binary from the Releases page.
linuxplorer is configured using the `linuxplorer` command.
Run the command with `--help` to see all available options.

### Basic configuration example
```bash
linuxplorer -p --create server1	# Create a profile 'server1'
linuxplorer -c server1@credential=<host>,<username>,<password>	# Set a host, username and password
linuxplorer -c server1@syncroot=C:\Users\user\server1	# Set a mount point

linuxplorer -i	# Start linuxplorer
linuxplorer -t	# Stop linuxplorer
```
> **Note**:
> Credential configuration is **non-interactive**.  
> Passwords are provided via command-line arguments and may be visible in shell history or process listings.  
> [Stored credentials are encrypted at rest. (AES + DPAPI)](https://github.com/koNinja/linuxplorer/blob/0ab79e24ce5993c72e8ba9974d55b8db8b755c2e/src/util/config/profiles.cpp#L14)  
> This handling will be improved in a future version.

After starting linuxplorer, the remote filesystem will appear
at the configured sync root in Windows Explorer.  
Log files are stored in `C:\Users\<username>\.linuxplorer\logs`.

### Startup configuration example
```bash
linuxplorer -c startup=[on/off]	# Enable or disable startup
```

### Uninstallation example
```bash
linuxplorer -t	# Stop linuxplorer
linuxplorer -p --remove server1	# Remove a profile 'server1'
rmdir /s C:\Users\<username>\.linuxplorer  # All app data is stored here
```

## Build Environment (tested)
This project uses CMake.
- Windows 11
- Visual Studio Code
- Visual Studio 2022 (MSVC)
- Ninja build 1.13.2+
- CMake 3.31+
- vcpkg (for dependencies)
### Dependencies
- [Cloud Filter API (Win32)](https://learn.microsoft.com/en-us/windows/win32/api/_cloudapi/)
- [libssh2](https://libssh2.org/)
- [nlohmann-json](https://github.com/nlohmann/json)
- [Boost](https://www.boost.org/)
- [OpenSSL](https://www.openssl.org/)
- [Quill](https://github.com/odygrd/quill)
- [GoogleTest](https://github.com/google/googletest)

## License
MIT License
