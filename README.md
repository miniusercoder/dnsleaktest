# dnsleaktest

A command-line tool implemented in Go to test for DNS leaks and DNS rebinding vulnerabilities.

This tool performs a comprehensive [BigDig](https://bigdig.energy/) DNS leak test, checking which DNS servers are actually resolving your requests. It can also perform a specific test for DNS rebinding vulnerabilities.

## Features

- **DNS Leak Test**: Verifies which DNS servers are handling your queries by making requests to unique subdomains.
- **DNS Rebinding Test**: Checks for rebinding vulnerabilities by performing periodic requests over a wait period (skipped in `short` mode).
- **Client IP Detection**: Fetches and displays client IP information.
- **Cross-Platform**: Ready-to-build for Linux, Windows, and macOS.

## Building

You need [Go](https://go.dev/) installed to build this project.

The project includes a `Makefile` to simplify the build process.

To build binaries for all supported platforms (Linux, Windows, macOS):

```bash
make build
```

The binaries will be created in the `build/` directory:
- `dnsleaktest-linux-amd64`
- `dnsleaktest-linux-arm64`
- `dnsleaktest-darwin-amd64`
- `dnsleaktest-darwin-arm64`
- `dnsleaktest.exe` (Windows)

To clean build artifacts:

```bash
make clean
```

## Usage

Run the compiled binary for your platform.

```bash
./build/dnsleaktest-linux-amd64 [flags]
```

### Flags

- `-short`: Run a short test. This only checks for DNS leaks and skips the longer DNS rebinding phase.
- `-version`: Print version information and exit.

### Examples

**Run a full test (Leak + Rebinding):**

```bash
./dnsleaktest
```
*Note: The full test includes a waiting period (approx. 70 seconds) to detect rebinding attempts.*

**Run a short test (Leak only):**

```bash
./dnsleaktest -short
```

## License

MIT License. See [LICENSE](LICENSE) file for details.

