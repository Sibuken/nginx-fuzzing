# Фаззинг nginx 1.30.5

Интеграция собирает текущий checkout nginx в отдельный Docker-образ. Исходники
nginx, production `Dockerfile` и каталог `tests` остаются без изменений.

Цель `NGX-OSS-HTTP` адаптирована из закреплённой ревизии OSS-Fuzz. Она использует
libFuzzer, ASan, UBSan и libprotobuf-mutator; входы представлены protobuf
text-format сообщениями с парами `request`/`reply`.

## Текущая область применения

| Цель | Проверяемая функциональность |
| --- | --- |
| `NGX-OSS-HTTP` | Обработка HTTP-запросов и ответов через интеграцию OSS-Fuzz. |
| `NGX-IF06` | Разбор PROXY protocol v1 и v2. |
| `NGX-IF07` | Разбор DNS-ответов и записей A, SRV и PTR. |
| `NGX-IF08` | Разбор TLV PROXY protocol v2, включая вложенные SSL TLV. |
| `NGX-IF09` | Лексический и командно-строчный разбор конфигурации nginx. |
| `NGX-IF10` | Декодирование целых чисел и Huffman-кодов HPACK. |
| `NGX-IF11` | Разбор заголовков кадров HTTP/2 и dispatch кадров. |
| `NGX-IF12` | Обработчики HTTP/2 SETTINGS, PING, GOAWAY и WINDOW_UPDATE. |
| `NGX-IF13` | Обработка HTTP/2 RST_STREAM. |
| `NGX-IF14` | HTTP/2 DATA, padding, приём и накопление тела запроса, фрагментация кадров и проверка `Content-Length`. |
| `NGX-IF15` | Декодирование HPACK-блоков заголовков с динамической таблицей и разбиением HEADERS/CONTINUATION. |
| `NGX-IF16` | Разбор HTTP/2 pseudo-заголовков `:method`, `:scheme` и `:path`, включая дубликаты. |
| `NGX-IF17` | Обработка HPACK-заголовков живого потока и проверка `:authority`. |
| `NGX-IF18` | Последовательности HEADERS/CONTINUATION, создание HTTP/2 stream и разбор HPACK. |
| `NGX-IF19` | Повторные HEADERS с тем же stream ID и обработка границы trailer-последовательности. |
| `NGX-IF20` | Формирование исходящих HTTP/2 trailers, сериализация HPACK и очередь DATA/HEADERS кадров, включая flow control и события записи. |
| `NGX-IF21` | Приём upstream HTTP/2 trailers в HEADERS/CONTINUATION и обработка предшествующих DATA-кадров. |

Дополнительные сведения о предпосылках и профилях каждой цели приведены в
`targets/<имя>/README.md` и `targets/<имя>/target.json`.

Все команды выполняются из корня репозитория. Обязательный профиль —
`linux/amd64`; на Apple Silicon он запускается через эмуляцию OrbStack.
Образ основан на закреплённом Debian 12 slim: это явно зафиксированная замена
недоступного внутреннего Astra registry, а не production-образ nginx.

## Сборка

```bash
./fuzz/scripts/fuzz.sh build
```

Compose-файл запускает только уже собранный образ; сборка выполняется отдельной
командой и перед `campaign-parallel` автоматически вызывается ровно один раз.

Сборка использует проверяемые архивы OSS-Fuzz и libprotobuf-mutator. Работа с
зеркалом и offline cache описана в `UPSTREAM.md`.

## Smoke и кампания

Smoke по умолчанию выполняет 60 секунд активного фаззинга и затем формирует
baseline/final LLVM coverage:

```bash
./fuzz/scripts/fuzz.sh smoke NGX-OSS-HTTP
./fuzz/scripts/fuzz.sh smoke-all
```

Кампания по умолчанию продолжается, пока не пройдёт 7200 секунд без нового
покрытия. Fuzzer запускается ограниченными fork-supervisor batches (по 300
секунд по умолчанию); после каждого batch runner объединяет корпус и проверяет
LLVM line/branch coverage. Прирост начинает окно плато заново. Это позволяет
остановить supervisor штатным `-max_total_time`, не теряя устойчивость к crash.
Перед подтверждением плато runner повторно измеряет весь сохранённый корпус;
если replay находит пропущенный прирост, кампания возобновляется.
В campaign mode libFuzzer работает под fork-supervisor с `-ignore_crashes=1`:
найденные crash inputs сохраняются как artifacts, но отдельный сбой не
останавливает кампанию. Они попадут в manifest и итоговый отчёт после остановки
по плато или лимиту времени. Smoke остаётся одно-процессным и завершается на
первой находке. Общий лимит времени по умолчанию выключен; при необходимости
его можно задать отдельно. Он
проверяется с той же периодичностью, поэтому фактическая остановка может
задержаться до одного интервала:

```bash
./fuzz/scripts/fuzz.sh campaign NGX-OSS-HTTP
./fuzz/scripts/fuzz.sh campaign NGX-OSS-HTTP \
  --plateau-seconds 7200 --coverage-check-interval-seconds 300 --max-seconds 86400
```

Перед каждой кампанией автоматически проверяются regression fixtures выбранной
цели. Известная sanitizer-находка считается успешной проверкой; если вход
перестаёт воспроизводить ASan/UBSan-диагностику, кампания не стартует. Вручную
проверить все сохранённые регрессии или одну цель можно так:

```bash
./fuzz/scripts/fuzz.sh regression-check
./fuzz/scripts/fuzz.sh regression-check NGX-IF14
```
Hex-файлы регрессий проверяются по декодированным входам, создаваемым при
сборке образа; preflight завершится ошибкой, если такой вход отсутствует.
Учитывается ненулевой код завершения вместе с ASan/UBSan-диагностикой, а не
любой случайный nonzero exit.

Бюджет и ограничения можно переопределить:

```bash
./fuzz/scripts/fuzz.sh smoke NGX-OSS-HTTP \
  --seconds 30 --seed 7 --max-len 65536 --timeout 10 --rss-limit-mb 2048
```

Узкие raw-input цели `NGX-IF06`, `NGX-IF07`,
`NGX-IF08`, `NGX-IF09`, `NGX-IF10`, `NGX-IF11`, `NGX-IF12`, `NGX-IF13` и
`NGX-IF14`—`NGX-IF21` запускаются теми же командами. Для файлового
синтаксиса nginx целесообразен реальный предел буфера 4096 байт:

```bash
./fuzz/scripts/fuzz.sh smoke NGX-IF09 --max-len 4096
./fuzz/scripts/fuzz.sh smoke NGX-IF10 --max-len 4096
./fuzz/scripts/fuzz.sh smoke NGX-IF11 --max-len 9
./fuzz/scripts/fuzz.sh smoke NGX-IF12 --max-len 4096
./fuzz/scripts/fuzz.sh smoke NGX-IF13 --max-len 4096
./fuzz/scripts/fuzz.sh smoke NGX-IF14 --max-len 4096
./fuzz/scripts/fuzz.sh smoke NGX-IF15 --max-len 4096
./fuzz/scripts/fuzz.sh smoke NGX-IF16 --max-len 4096
./fuzz/scripts/fuzz.sh smoke NGX-IF17 --max-len 4096
./fuzz/scripts/fuzz.sh smoke NGX-IF18 --max-len 8192
./fuzz/scripts/fuzz.sh smoke NGX-IF19 --max-len 8192
./fuzz/scripts/fuzz.sh smoke NGX-IF20 --max-len 65536
./fuzz/scripts/fuzz.sh smoke NGX-IF21 --max-len 16384
```

Корпуса хранятся как обычные файлы в `corpus_in/` и `corpus_out/`, чтобы их
можно было просматривать и использовать напрямую:

```bash
./fuzz/scripts/fuzz.sh campaign NGX-OSS-HTTP \
  --reuse-corpus /runs/NGX-OSS-HTTP/<run-id>/corpus_out
```

Каждый запуск создаёт отдельный каталог `fuzz/runs/<target>/<run-id>/` с
manifest, отчётом, находками, словарём, сжатыми логами раундов, компактной
сводкой покрытия и несжатыми корпусами. Временные `.profraw` удаляются сразу после
слияния; промежуточная проверка покрытия использует один переиспользуемый
профиль вместо отдельной копии корпуса и полного набора профилей на каждый
раунд. Детальные line/branch ID остаются только в памяти во время проверки,
а в итоговом manifest хранятся счётчики покрытия.

Так результаты не раздуваются из-за дублирующих snapshots и временных профилей;
их размер определяется самими входами корпуса, crash artifacts и отчётами.

`smoke-all` всегда пытается запустить все настроенные цели. Campaigns
продолжают работу после sanitizer crash и в конце возвращают manifest со
статусом `finding`; это не считается ошибкой оркестрации.

### Параллельные кампании

Одного образа достаточно: при сборке в него включаются все target-бинарники,
а команда `campaign TARGET` выбирает нужный интерфейс. `campaign-parallel`
сначала один раз собирает общий image, затем запускает все цели (или выбранные
цели явно):

```bash
./fuzz/scripts/fuzz.sh campaign-parallel --jobs 4
./fuzz/scripts/fuzz.sh campaign-parallel --jobs 4 \
  NGX-OSS-HTTP NGX-IF14 NGX-IF18 NGX-IF20 NGX-IF21
```

По умолчанию запускаются все настроенные targets, одновременно не более четырёх.
`--jobs` ограничивает число работающих контейнеров; значение можно также
задать через `FUZZ_PARALLEL_JOBS`. Каждый запуск использует один локальный образ,
но отдельный Compose project name (`-p`) и уникальный run ID; отчёты совместно
пишутся в `fuzz/runs/<target>/` и не перезаписывают друг друга. Сборка вынесена
из Compose service и выполняется отдельно один раз перед стартом worker-ов.
Все проекты подключаются к постоянной внешней сети `nginx-fuzz-shared`, которую
orchestrator создаёт только при отсутствии; Compose не создаёт отдельную сеть
для каждого проекта и не скачивает image. Уменьшайте `--jobs`
на машинах с ограниченной памятью: каждый процесс фаззинга имеет собственный
лимит RSS.

## Проверка seed и воспроизведение

Проверки классификации результатов раннера запускаются стандартной библиотекой Python:

```sh
python3 -m unittest discover -s fuzz/tests
```

Проверка и канонический просмотр protobuf text-format seed:

```bash
./fuzz/scripts/fuzz.sh inspect-seed \
  /opt/fuzz/seeds/NGX-OSS-HTTP/valid-get.textproto
```

Воспроизведение сохранённого input с ASan/UBSan:

```bash
./fuzz/scripts/fuzz.sh reproduce NGX-OSS-HTTP \
  /runs/NGX-OSS-HTTP/<run-id>/artifacts/<input>
```

Тот же adapter без санитайзеров, в coverage-сборке:

```bash
./fuzz/scripts/fuzz.sh reproduce NGX-OSS-HTTP \
  /runs/NGX-OSS-HTTP/<run-id>/artifacts/<input> \
  --without-sanitizers
```

Подтверждённый короткий regression input для обнаруженного UBSan-дефекта уже
включён в образ:

```bash
./fuzz/scripts/fuzz.sh reproduce NGX-OSS-HTTP \
  /opt/fuzz/regressions/NGX-OSS-HTTP/nonnull-zero-length.textproto
```

Второй regression input воспроизводит signed overflow в chunked parser:

```bash
```

Два DNS regression input воспроизводят signed left shift при
декодировании TTL и IPv4-адреса:

```bash
./fuzz/scripts/fuzz.sh reproduce NGX-IF07 \
  /opt/fuzz/regressions/NGX-IF07/ttl-left-shift
./fuzz/scripts/fuzz.sh reproduce NGX-IF07 \
  /opt/fuzz/regressions/NGX-IF07/a-address-left-shift
```

Канонический 10-байтовый IF14 regression input воспроизводит UBSan pointer
overflow в HTTP/2 DATA/preread handler:

```bash
./fuzz/scripts/fuzz.sh reproduce NGX-IF14 \
  /opt/fuzz/regressions/NGX-IF14/data-preread-null-offset
```

Повторный coverage replay и минимизация корпуса (с проверкой точного множества
покрытых scope-строк):

```bash
./fuzz/scripts/fuzz.sh coverage NGX-OSS-HTTP <run-id>
./fuzz/scripts/fuzz.sh minimize-corpus NGX-OSS-HTTP <run-id>
./fuzz/scripts/fuzz.sh minimize-crash NGX-OSS-HTTP \
  /runs/NGX-OSS-HTTP/<run-id>/artifacts/<input> \
  /runs/NGX-OSS-HTTP/<run-id>/defects/<input>.min
```

## Текущая область применимости

`NGX-OSS-HTTP` подаёт HTTP/1 запрос и ответ синтетического upstream во
внутрипроцессное reverse-proxy окружение nginx. Фактическая достижимость
областей самого adapter отражается в coverage-отчёте этой цели. Широкий adapter не
принимает HTTP/2 wire input, поэтому HPACK primitives, frame header и тела
control frames вынесены в `NGX-IF10`/`NGX-IF11`/`NGX-IF12`/`NGX-IF13`/`NGX-IF14`. TLS, HTTP/3, реальная
файловая раздача, production location/rewrite, DNS resolver и мутируемая
конфигурация этой целью не проверяются. DNS response parser и
синтаксис конфига вместо этого измеряются отдельными `NGX-IF07` и
`NGX-IF09`. `NGX-IF12` моделирует постоянное состояние control frames и один
  синтетический stream для WINDOW_UPDATE; `NGX-IF13` вызывает RST_STREAM на этом
  stream, а `NGX-IF14` принимает DATA в preread, bounded request-body filter
  profile и последовательности нескольких DATA frames. Downstream body filters,
  полный stream/request lifecycle и построение request из HEADERS/CONTINUATION
  не моделируются.


## Матрица сценариев

| Сценарий | Что реально проверяется |
| --- | --- |
| HTTP/1 reverse proxy | Да: request/reply проходят embedded proxy-конфигурацию `NGX-OSS-HTTP` |
| HTTP/1 request line | Да: интегрированная обработка в `NGX-OSS-HTTP` |
| HTTP/1 chunked framing | Да: интегрированная обработка в `NGX-OSS-HTTP` |
| PROXY protocol v1/v2 | Да, parser-only в `NGX-IF06`; TLV и nested SSL TLV в `NGX-IF08`; listener integration не проверяется |
| DNS response parser | Да: A, AAAA, CNAME, SRV, IPv4 PTR и malformed wire responses в `NGX-IF07`; сетевые timeout/retry не проверяются |
| TLS | Нет: OpenSSL не подключён, handshake отсутствует |
| HTTP/2 | Частично: HPACK Huffman/integer в `NGX-IF10`, frame header/type dispatch в `NGX-IF11`, реальные SETTINGS/PING/GOAWAY/WINDOW_UPDATE в `NGX-IF12`, RST_STREAM в `NGX-IF13`, DATA/preread и request-body filter в `NGX-IF14`, HPACK block/dynamic table и valid CONTINUATION payloads в `NGX-IF15`, method/scheme/path в `NGX-IF16`, HPACK-to-live-request headers и authority virtual-host match в `NGX-IF17`, raw HEADERS/CONTINUATION → stream/request в `NGX-IF18`, повторный HEADERS на существующем stream и его раннее отклонение в `NGX-IF19`, исходящие trailers в `NGX-IF20`, upstream response trailers в `NGX-IF21`; полный request pipeline остаётся вне охвата |
| HTTP/3/QUIC | Нет |
| Статические файлы | Нет: профиль направляет запрос в synthetic upstream |
| Routing/rewrite | Только фиксированные `server`/`location`/`map` embedded-профиля |
| Config parser | Частично: lexer, quotes/escapes/variables/comments и `ngx_conf_param` в `NGX-IF09`; module directive semantics и `include` не проверяются |

Короткий smoke подтверждает работоспособность, но не является полной кампанией
и не подтверждает двухчасовое плато. Компактные отчёты и артефакты хранятся в
`fuzz/runs/`, а корпуса доступны в `corpus.tar.gz` внутри каталога запуска.

Campaign использует fork-supervisor и продолжает работу после отдельных
sanitizer crashes. Coverage observer сравнивает LLVM line/branch coverage по
сохранённым новым входам корпуса; он не измеряет coverage transient inputs,
которые libFuzzer не сохранил. Smoke остаётся запуском с фиксированным
`--seconds` и не использует критерий плато.
