# NGX-OSS-HTTP regressions

`nonnull-zero-length.textproto` — минимизированный вручную воспроизводитель
UBSan `nonnull-attribute` в `ngx_http_proxy_create_request` на
`src/http/modules/ngx_http_proxy_module.c:1367`. Absolute-form URI имеет
пустой path и query delimiter; nginx вызывает `ngx_copy`/`memcpy` с нулевой
длиной и null source. Sanitizer build завершается с кодом 77, coverage build
завершается с кодом 0. Исходники nginx намеренно не изменены.
