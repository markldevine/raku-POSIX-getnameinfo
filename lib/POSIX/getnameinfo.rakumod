unit module POSIX::getnameinfo:ver<0.0.1>:auth<zef:markldevine>;

use NativeCall;

constant NI_MAXHOST is export = 1025;
constant NI_MAXSERV is export = 32;

# Address families
constant AF_INET    is export = 2;
constant AF_INET6   is export = $*KERNEL.name eq 'darwin' ?? 30 !! 10;

enum NameInfoFlags is export (
    NI_NOFQDN        => 0x01,
    NI_NUMERICHOST   => 0x02,
    NI_NAMEREQD      => 0x04,
    NI_NUMERICSERV   => 0x08,
    NI_DGRAM         => 0x10,
);

# Low-level POSIX getnameinfo signature
sub getnameinfo(
    Pointer, uint32,
    CArray[uint8], uint32,
    CArray[uint8], uint32,
    int32
) returns int32 is native { * }

# inet_pton for populating binary addresses cleanly
sub inet_pton(int32, Str, Pointer) returns int32 is native { * }

# Address inner structs so we get direct pointers without pointer math
class InAddr is repr('CStruct') {
    has uint32 $.s_addr is rw;
}

class In6Addr is repr('CStruct') {
    has uint64 $.s6_addr_hi is rw;
    has uint64 $.s6_addr_lo is rw;
}

class SockAddrIn is repr('CStruct') {
    has uint16 $.sin_family is rw;
    has uint16 $.sin_port   is rw;
    HAS InAddr $.sin_addr;
    has uint64 $.sin_zero   is rw;
}

class SockAddrIn6 is repr('CStruct') {
    has uint16 $.sin6_family   is rw;
    has uint16 $.sin6_port     is rw;
    has uint32 $.sin6_flowinfo is rw;
    HAS In6Addr $.sin6_addr;
    has uint32 $.sin6_scope_id is rw;
}

class NameInfoResult is export {
    has Str $.host;
    has Str $.service;

    method gist(--> Str) { "Host: $.host, Service: $.service" }
}

# Clean htons with explicit precedence parens
sub htons(Int $port --> uint16) {
    (($port +& 0xFF) +< 8) +| (($port +> 8) +& 0xFF);
}

proto sub Get-Name-Info(|) is export { * }

multi sub Get-Name-Info(Str $ip, Int $port = 0, Int $flags = 0 --> NameInfoResult) {
    my $host-buf = CArray[uint8].allocate(NI_MAXHOST);
    my $serv-buf = CArray[uint8].allocate(NI_MAXSERV);

    my ($sockaddr-ptr, $socklen);

    if $ip.contains(':') {
        my $sa6 = SockAddrIn6.new;
        $sa6.sin6_family = AF_INET6;
        $sa6.sin6_port   = htons($port);

        # Direct pointer to the embedded struct - zero manual pointer math
        my $addr-ptr = nativecast(Pointer, $sa6.sin6_addr);
        fail "Invalid IPv6 address: $ip" unless inet_pton(AF_INET6, $ip, $addr-ptr) == 1;

        $sockaddr-ptr = nativecast(Pointer, $sa6);
        $socklen      = nativesizeof(SockAddrIn6);
    }
    else {
        my $sa4 = SockAddrIn.new;
        $sa4.sin_family = AF_INET;
        $sa4.sin_port   = htons($port);

        # Direct pointer to the embedded struct - zero manual pointer math
        my $addr-ptr = nativecast(Pointer, $sa4.sin_addr);
        fail "Invalid IPv4 address: $ip" unless inet_pton(AF_INET, $ip, $addr-ptr) == 1;

        $sockaddr-ptr = nativecast(Pointer, $sa4);
        $socklen      = nativesizeof(SockAddrIn);
    }

    my $ret = getnameinfo(
        $sockaddr-ptr, $socklen,
        $host-buf, NI_MAXHOST,
        $serv-buf, NI_MAXSERV,
        $flags
    );

    if $ret != 0 {
        fail "getnameinfo failed with error code $ret";
    }

    my sub buf-to-str(CArray[uint8] $buf --> Str) {
        my @bytes;
        loop (my $i = 0; $buf[$i] != 0; $i++) {
            @bytes.push($buf[$i]);
        }
        return Blob.new(@bytes).decode('utf-8');
    }

    return NameInfoResult.new(
        host    => buf-to-str($host-buf),
        service => buf-to-str($serv-buf)
    );
}
