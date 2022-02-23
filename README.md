# Hall

Hall is a fork of the original [Grumble](https://github.com/mumble-voip/grumble) server.  

## What is Hall?

Hall is an implementation of a server for the Mumble voice chat system. It is an alternative to Murmur, the typical Mumble server.

## Compiling Hall from source

You must have a Go 1 environment installed to build Hall. Those are available at:

https://golang.org/dl/

Run the following command to build Chinese localized version:

    $ make clean
    $ make zh

Or the English version:

    $ make clean
    $ make en

And that should be it. Hall has been built, and is available in working directory as 'hall'.

## Is it stable enough?

The server published here is generally stable. Experiments are done in other locations.

## Configuration

See `config.go`.

## Capabilities

### Version supported

The protocol version supported by the server is specified in `version.go` as `verProtover`.

### Extra features Murmur don't have

 - More than 1 session per User ID, and fine-grained control over how many sessions a user can have.
 - GeoIP based ACL
 - Better multi-core utilization and locking mechanism
 - Less crash and more robust with slow external authenticator
 - Config hot-reload
 - Certificate hot-reload
 - Automatically determine if a connection is droppy and disable UDP accordingly.
 - `sendmmsg` support that reduces syscall overhead by sending UDP packets in batches.
 - Proxy protocol support

### Extra features Grumble don't have

 - Database support (SQLite only currently, but can be ported easily)
 - Authentication via HTTP (`rpc.go`) and periodically user list sync.
 - Optimized performance for thousands of clients on low-end hardware.

### Not implemented

 - User Textures are not implemented.
 - Local user databases is stripped away since I don't use them.
 - Only a part of ACL Group directives are implemented. See `group.go` for details.
 - Temporary channels are not implemented. I still haven't found an elegant solution to implement this feature with minimal impact to database.
 - Import from Murmur database is not implemented. I don't use this as well but PRs are welcome.
 - User list is empty. The server does not store user information (nor in offline cached mode).
 - Websocket server is stripped away. Are there actually any user that use it?

## TBD

 - Docker files
 - License craps
 - Cleanups
