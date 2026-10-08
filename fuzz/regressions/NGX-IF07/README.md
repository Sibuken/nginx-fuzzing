# NGX-IF07 regressions

`ttl-left-shift.hex` is a minimized raw DNS-response testcase. Byte 0 selects
UDP; the response contains one AAAA answer whose TTL starts with `0xff`.
`ngx_resolver_process_a` promotes that byte to signed `int` and evaluates
`an->ttl[0] << 24`, which UBSan reports as an unrepresentable signed left shift
at `src/core/ngx_resolver.c:2197`. The sanitizer build exits with code 77 and
the coverage build exits with code 0. Production nginx sources are unchanged.

`a-address-left-shift.hex` reaches the analogous conversion of an IPv4 answer:
the first address octet is `0xc0`, and `buf[i] << 24` triggers the same UBSan
class at `src/core/ngx_resolver.c:2359`. It also exits with code 77 only in the
sanitizer build.
