# CERT-VERIFICATION-CANON — единая последовательность верификации серверного сертификата

> Канон для трёх реализаций семьи: **ssh3-go** (эталон), **ssh3-c**, **ssh3-rust**.
> Составлен 2026-11-04 по итогам анализа кода (cmd/ssh3.go, known_hosts.go, ssh3_client.c,
> s3_ssl.c) и тезисов владельца. Пункты в планах реализаций ссылаются сюда:
> ssh3-go R5, ssh3-c PLAN-CURRENT (Блок 2), ssh3-rust ROADMAP (отложено).

Контекст развёртывания (решение владельца): ssh3 — экспериментальный, готов к эксплуатации **в LAN,
не WAN**; белые IPv4 у клиентов не ожидаются, реальные IPv6 возможны; сертификаты —
CA-выпуск (DNS-01, или TLS-ALPN-01 через временно открытый TCP/443) либо self-signed+TOFU.

## 1. Термины

| Термин | Значение |
|--------|----------|
| Якорь доверия | То, во что упирается проверка цепочки: системный CA-стор, пин цели, SSHFP-зона |
| Цель (target) | Строка `host:port/urlPath` — **ключ пина** (`CanonicalHostFormat`); разные написания одного сервера (имя/IP/v4/v6) — разные пины |
| Лист | Peer-сертификат из TLS-хендшейка |
| Первый контакт | Подключение, для которого у цели ещё нет пина |

## 2. Последовательность действий клиента

| № | Шаг | Семантика |
|---|-----|-----------|
| 2.1 | `-insecure` | Полная деградация: без цепочки, без пинов; dev-only, маркер в логе |
| 2.2 | Хендшейк | Якорь = пины цели **∪** системные CA (обе группы добавляются в trust pool); цепочка проверяется **всегда**; SAN/hostname верифицируется против цели (selfsigned.ssh3-хак допустим только когда пин не несёт IP SAN) |
| 2.3 | Сверка листа с пинами | `Matches` → соединение. `Changed` → **отказ** (MITM-детектор), кроме `-o StrictHostKeyChecking=no`. `Unknown` → первый контакт: цепочка CA-валидна → принять (якорь — CA; пин записывается при `accept-new`); self-signed → пин при `accept-new` **с out-of-band сверкой fingerprint** (при `yes` — отказ) |
| 2.4 | Renewal-семантика | Лист не совпал с пином, **но** цепочка CA-валидна **и** SAN покрывает цель → легитимная ротация: обновить пин (лог «certificate rotated, chain valid»), соединить. Self-signed ротация — через SSHFP-перепин (удалить пин → reconnect → SSHFP сверяет новый лист). Без этого пункта каждый легитимный renewal выглядит для клиентов как атака |
| 2.5 | SSHFP | При `VerifyHostKeyDNS`: fingerprint листа против SSHFP в зоне; mismatch → отказ; match → проверяемый перепин. SSHFP **не** обходит 2.3-отказ по `Changed` — он делает re-pin достоверным |

### 2.6 AIA-докачивание промежуточных сертификатов (ssh3-go R7-T2)

Хендшейк падает по цепочке, когда сервер не предъявил (и пул не держит) промежуточные
сертификаты — якоря в сторе есть. Недостающие intermediates добираются по
`caIssuers`-URL (RFC 5280 4.2.2.1) предъявленных сертификатов, рекурсивно вверх.

| № | Правило |
|---|---------|
| 1 | Триггер: crypto-error хендшейка + leaf не self-signed (self-signed — территория TOFU-потоков 2.3) + цепочка ещё не верифицируется к якорям. Capture-диал (verify-колбэк с выключенной верификацией) достаёт предъявленные сертификаты |
| 2 | Чейз: caIssuers-URL верхнего предъявленного серта, рекурсивно; DER и PEM ответы оба разрешены (браузерная семантика); глубина ≤8, таймаут fetch ≤5 с, бюджет ≤20 с на чейз, кап тела ответа |
| 3 | **Гейт**: докачанное ходит только intermediates'ами в `leaf.Verify(Roots: якорный пул (стор ∪ embed ∪ бандл ∪ пины), Intermediates: предъявленные ∪ докачанные)`; в якорный пул не попадает никогда. Реализация: retry-хендшейк с `InsecureSkipVerify`+`VerifyConnection` (std crypto/tls не умеет инжектировать intermediates без `RootCAs`, а каждая запись пула — потенциальный якорь); не выстроилось к якорю — отброшено, подмена http-ответа MITM'ом нейтрализуется гейтом |
| 4 | Кэш: `~/.ssh3/aia-cache/` (PEM, 0600, ключ — SHA-256 caIssuers-URL; рядом с остальным состоянием клиента, путь `~/.config/ssh3/` свёрнут); тёплый кэш — ноль сетевых запросов на следующих диалах; офлайн — stale-кэш; провал гейта на кэше → один network-forced проход (stale/poisoned запись не клинит клиента); просроченная копия гейт не проходит — stale доверие не верифицируется |
| 5 | Вердикты пинов (2.3–2.5) едут на AIA-completed соединении как на любом другом; AIA-трафик светит IP клиента стороне CA (оператору CA), но не целевому хосту |

C-специфика (ssh3-c, 2026-11-11): retry-хендшейк не нужен — клиент верифицирует **record-only** (первая фатальная X509-ошибка пишется в `s3_ssl_t.chain_err`, хендшейк жив, энфорсмент ssh3-слоя), поэтому чейз запускается пост-хендшейк на missing-issuer классе вердикта (`UNABLE_TO_GET_ISSUER_CERT[_LOCALLY]`, `UNABLE_TO_VERIFY_LEAF_SIGNATURE`) при не-self-signed листе и достраивает цепочку офлайн-верификацией `X509_STORE_CTX`: якоря = стор клиентского CTX (system ∪ embedded ∪ bundle ∪ пины, PARTIAL_CHAIN), предъявленные + докачанные — untrusted, в якорный стор не попадают; успех сбрасывает вердикт до машины 2.3–2.5. Якоря чейза включают T1-bootstrap (`s3_ssh3_aia_trust_bootstrap`: зашитые ISRG X1/X2 + `SSH3_CA_BUNDLE`/`~/.ssh3/ca-bundle.pem`). Реализация — `ssh3-c/src/ssh3/s3_ssh3_aia.{c,h}`, кэш — `~/.ssh3/aia-cache/<SHA-256(url)>.pem`.

## 3. Обязанности сервера

| № | Обязанность |
|---|-------------|
| 3.1 | Сертификат: CA-выпуск (DNS-01 — предпочтительно; TLS-ALPN-01 через временно открытый TCP/443, окно open→issue→close в одной сессии) или self-signed+TOFU (LAN) |
| 3.2 | Ротация: SSHFP-запись новой версии — до/сразу после ротации; SAN покрывает все имена цели; никаких скрытых ротаций без SSHFP/уведомления |
| 3.3 | Релизный клиент не носит keylog-колбэк (отладка — отдельной сборкой) |

## 4. Сверка реализаций (2026-11-04; ssh3-c — 2026-11-05, ssh3-go — 2026-11-11)

| Пункт канона | ssh3-go | ssh3-c | ssh3-rust |
|--------------|---------|--------|-----------|
| 2.2 якорь CA ∪ пины | ✅ (`certPool`, системные CA) | ✅ 2026-11-05 — record-only verify-колбэк, вердикт в `s3_ssl_t.chain_err` (`66f5180`); якорь = пины (`s3_ssl_client_add_pin`, PARTIAL_CHAIN) ∪ `set_default_verify_paths`; энфорсмент ssh3-слоем до credential'ов | заявлено в волне 7 — сверить |
| 2.2 SAN против цели | ✅ (TLS hostname verify + selfsigned-хак) | ✅ 2026-11-05 — пост-хендшейк `X509_check_host`/`X509_check_ip` против цели (`s3_cli_san_ok`); selfsigned.ssh3-хака нет: record-only вердикт не нуждается в подмене ServerName — пин-якорь покрывает самоподписанный лист без IP SAN | заявлено — сверить |
| 2.3 Matches/Changed/Unknown | ✅ (`CheckCertificate`, accept-new, `StrictHostKeyChecking`) | ✅ 2026-11-05 — машина `s3_hostkey_decide` (`5ede8fb`): Unknown/Changed/Matches + SHK ask (дефолт)/yes/no/accept-new (автопин), TOFU-промпт сохранён | заявлено — сверить |
| 2.4 renewal-семантика | ✅ — CA-ротация 2026-11-05 (`ab129e4`): CHANGED + chain CA-valid + SAN → `ReplaceKnownHost` (лог «certificate rotated, chain valid»); self-signed 2026-11-11 (`2dd5589`): SSHFP VERIFIED → перепин (лог «certificate rotated, sshfp verified»), без DNS-сигнала — отказ | ✅ 2026-11-05 — CHANGED + chain CA-valid + SAN → перепин (`s3_cli_kh_replace`, лог «certificate rotated, chain valid»); self-signed ротация — через SSHFP-перепин | — (после сверки) |
| 2.5 SSHFP | ✅ (`checkHostKeySSHFP`; verified → перепин CHANGED-самоподписанного, `2dd5589`) | ✅ 2026-11-05 — `s3_ssh3_sshfp` (`c00139b`, порт sshfp.go 1:1, сырой DNS по UDP), `-o VerifyHostKeyDNS=yes|ask|no`, mismatch → отказ, verified → перепин CHANGED-самоподписанного | — (после сверки) |
| 2.6 AIA-докачивание | ✅ 2026-11-11 — `cmd/aia.go` + retry-верификация в `cmd/ssh3.go` (R7-T2: caIssuers-чейз, гейт через `Intermediates`-пул `x509.Verify`, кэш `~/.ssh3/aia-cache/`, офлайн на stale-кэше; fetched в якорный пул не попадает) | ✅ 2026-11-11 — `src/ssh3/s3_ssh3_aia.{c,h}` (зеркало R7-T2, в рабочем дереве): missing-issuer триггер → пост-хендшейк caIssuers-чейз без retry-хендшейка (record-only семантика B-вер), гейт — офлайн `X509_STORE_CTX` (fetched untrusted, якоря не растут), кэш `~/.ssh3/aia-cache/` SHA-256(url)→PEM 0600, stale/poisoned → network-forced pass; капы: глубина 8 / fetch 5 с / бюджет 20 с / тело 256 КиБ; юниты `tests/test_ssh3_aia.c` (fetch-хук, сеть запрещена), e2e `interop/aia-chase-e2e.sh` OK. T1 (bootstrap: embedded ISRG X1/X2 + `SSH3_CA_BUNDLE`/`~/.ssh3/ca-bundle.pem`) закрыт той же волной | — |
| 3.3 keylog в релизе | ок | ✅ 2026-11-05 — keylog-cb в клиентском CTX только при `S3_KEYLOG`; `-keylog`-файл остался у интероп-харнеса | сверить |

Приёмка ssh3-c: ctest 51/51 (release+asan), mingw чисто; e2e `ssh3-c/interop/cert-verify-e2e.sh` — CA-первый-контакт, renewal-перепин, self-signed accept-new, ask non-console, SSHFP mismatch/verified/soften (python-стаб DNS), keylog-гейт. Детали — `ssh3-c/docs/PLAN-CURRENT.md` (Блок 2, B-вер).

## 5. Приоритеты (решение владельца 2026-11-04)

1. **ssh3-c** — критично: единственный якорь клиента — пин; первый контакт не защищён даже CA-сертификатом; план — пункт в `ssh3-c/docs/PLAN-CURRENT.md` (Блок 2). **Закрыто 2026-11-05** (см. §4).
2. **ssh3-go** — средне (удобство, не безопасность): renewal-семантика — пункт в `docs/ROADMAP.local.md` R5.
3. **ssh3-rust** — проверка отложена владельцем; пункт в `ROADMAP.md`.
