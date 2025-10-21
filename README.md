# grisp_keychain

Common layer to access secrets and identities on GRiSP devices. The app provides a basic module limited to filesystem based handling, but it can be configured to use backends like [grisp_cryptoauth](https://github.com/grisp/grisp_cryptoauth).

## Build

    $ rebar3 compile

## Configuration

The `grisp_keychain` application provides flexible configuration options for TLS certificate and key management. Configuration is done through the application environment (typically in `sys.config`).

### Configuration

The implementation module to use for the keychain API.
Defaults to `grisp_keychain_filesystem`.

```erlang
{grisp_keychain, [
    {api_module, grisp_keychain_filesystem}
]}
```

### TLS Configuration Options for `grisp_keychain_filesystem`

#### `tls_use_client_certificate`
**Type:** `boolean()`
**Default:** `true`
**Description:** Enable or disable the use of client certificates for TLS connections.

```erlang
{tls_use_client_certificate, false}
```

#### `tls_verify`
**Type:** `verify_none | verify_peer`
**Default:** `verify_peer`
**Description:** Set the TLS verification mode.
- `verify_peer`: Verify the server certificate (recommended for production)
- `verify_none`: Skip server certificate verification (useful for testing)

```erlang
{tls_verify, verify_peer}
```

### Certificate and Key Paths

#### `client_certs`
**Type:** `path_spec()`
**Required:** Yes (if `tls_use_client_certificate` is `true`)
**Description:** Path to client certificate(s). Can point to a single file or a directory containing multiple certificates.

```erlang
{client_certs, {priv, my_app, "certs/client.pem"}}
```

#### `client_key`
**Type:** `path_spec()`
**Required:** Yes (if `tls_use_client_certificate` is `true`)
**Description:** Path to the client private key file.

```erlang
{client_key, {priv, my_app, "keys/client.key"}}
```

#### `tls_client_trusted_certs`
**Type:** `path_spec()`
**Default:** `{priv, grisp_keychain, ""}`
**Description:** Path to trusted client certificates (CA certificates that can verify the client cert).

```erlang
{tls_client_trusted_certs, {priv, my_app, "certs/ca"}}
```

#### `tls_server_trusted_certs`
**Type:** `path_spec()`
**Optional**
**Description:** Base path to server trusted certificates. When provided with a domain name, the system will look for certificates in `<base_path>/<domain_name>`.

```erlang
{tls_server_trusted_certs, {priv, my_app, "certs/servers"}}
```

### Certificate Callback Functions

#### `tls_client_trusted_certs_cb`
**Type:** `callback_spec()`
**Optional**
**Description:** Callback function that returns additional client trusted certificates.

```erlang
{tls_client_trusted_certs_cb, {my_module, get_client_certs}}
% or with arguments:
{tls_client_trusted_certs_cb, {my_module, get_certs, [client]}}
```

#### `tls_server_trusted_certs_cb`
**Type:** `callback_spec()`
**Optional**
**Description:** Callback function that returns additional server trusted certificates.

```erlang
{tls_server_trusted_certs_cb, {my_module, get_server_certs}}
```

### Path Specification Format

Paths can be specified in multiple formats:

1. **Absolute path as string:**
   ```erlang
   "/absolute/path/to/cert.pem"
   ```

2. **Binary path:**
   ```erlang
   <<"/absolute/path/to/cert.pem">>
   ```

3. **Tuple format (relative to application directory):**
   ```erlang
   {priv, AppName, RelativePath}  % Relative to priv directory
   {test, AppName, RelativePath}  % Relative to test directory
   ```

### Callback Specification Format

Callbacks can be specified as:

1. **Module and function:**
   ```erlang
   {ModuleName, FunctionName}
   ```

2. **Module, function, and arguments:**
   ```erlang
   {ModuleName, FunctionName, [Arg1, Arg2, ...]}
   ```

The callback function should return a list of certificates in DER format.

## API Usage

### `grisp_keychain:tls_options/1`

Get TLS options for a specific domain.

```erlang
Options = grisp_keychain:tls_options(<<"example.com">>),
ssl:connect("example.com", 443, Options).
```

The domain parameter can be:
- `atom()` - e.g., `'example.com'`
- `string()` - e.g., `"example.com"`
- `binary()` - e.g., `<<"example.com">>`
- `undefined` - disables Server Name Indication

### `grisp_keychain:read_cert/2`

Read the primary client certificate in DER format.

```erlang
DerCert = grisp_keychain:read_cert(primary, der).
```

## Example Configuration

```erlang
{grisp_keychain, [
    {api_module, grisp_keychain_filesystem},
    {tls_use_client_certificate, true},
    {tls_verify, verify_peer},
    {client_certs, {priv, my_app, "certs/client.pem"}},
    {client_key, {priv, my_app, "keys/client-key.pem"}},
    {tls_client_trusted_certs, {priv, my_app, "certs/ca"}},
    {tls_server_trusted_certs, {priv, my_app, "certs/servers"}}
]}
```

## Certificate File Formats

- **Certificates:** PEM format (`.pem` or `.crt` extensions)
- **Keys:** PEM format, unencrypted only
- **Directory loading:** When a directory path is provided, all `.pem` and `.crt` files in that directory will be loaded
