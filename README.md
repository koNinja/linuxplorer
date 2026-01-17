# linuxplorer
**The portable SFTP client integrated with Windows Explorer.**

## Overview
<img width="60%" alt="Screenshot 2026-01-17 155000" src="https://github.com/user-attachments/assets/4713f383-6fdf-460a-ac85-4d722a18c3b3" />

linuxplorer is a personal project that integrates remote Linux files accessed via SFTP into Windows Explorer.

It aims to provide an experience similar to OneDrive or Dropbox,
but is **not intended to be a production-ready replacement**.
This project is intended for developers who want to browse remote
Linux files from Windows Explorer for personal or experimental use.

## Features
- Integration with Windows Explorer
- No installation required
- No admin privileges
- On-demand file access

## Requirements
- Windows 10 1709 or higher

## Notes
- Experimental and potentially unstable
- Not as stable as commercial products (e.g. OneDrive, Dropbox)
- Provided as-is, without any warranty
- Use at your own risk

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
Credentials handling is currently basic and will be improved in a future version.  
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
- [libssh2](https://libssh2.org/)
- [nlohmann-json](https://github.com/nlohmann/json)
- [Boost](https://www.boost.org/)
- [OpenSSL](https://www.openssl.org/)
- [Quill](https://github.com/odygrd/quill)
- [GoogleTest](https://github.com/google/googletest)

## License
MIT License
