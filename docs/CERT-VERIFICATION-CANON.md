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

## 3. Обязанности сервера

| № | Обязанность |
|---|-------------|
| 3.1 | Сертификат: CA-выпуск (DNS-01 — предпочтительно; TLS-ALPN-01 через временно открытый TCP/443, окно open→issue→close в одной сессии) или self-signed+TOFU (LAN) |
| 3.2 | Ротация: SSHFP-запись новой версии — до/сразу после ротации; SAN покрывает все имена цели; никаких скрытых ротаций без SSHFP/уведомления |
| 3.3 | Релизный клиент не носит keylog-колбэк (отладка — отдельной сборкой) |

## 4. Сверка реализаций (2026-11-04; ssh3-c колонка обновлена 2026-11-05)

| Пункт канона | ssh3-go | ssh3-c | ssh3-rust |
|--------------|---------|--------|-----------|
| 2.2 якорь CA ∪ пины | ✅ (`certPool`, системные CA) | ✅ 2026-11-05 — record-only verify-колбэк, вердикт в `s3_ssl_t.chain_err` (`66f5180`); якорь = пины (`s3_ssl_client_add_pin`, PARTIAL_CHAIN) ∪ `set_default_verify_paths`; энфорсмент ssh3-слоем до credential'ов | заявлено в волне 7 — сверить |
| 2.2 SAN против цели | ✅ (TLS hostname verify + selfsigned-хак) | ✅ 2026-11-05 — пост-хендшейк `X509_check_host`/`X509_check_ip` против цели (`s3_cli_san_ok`); selfsigned.ssh3-хака нет: record-only вердикт не нуждается в подмене ServerName — пин-якорь покрывает самоподписанный лист без IP SAN | заявлено — сверить |
| 2.3 Matches/Changed/Unknown | ✅ (`CheckCertificate`, accept-new, `StrictHostKeyChecking`) | ✅ 2026-11-05 — машина `s3_hostkey_decide` (`5ede8fb`): Unknown/Changed/Matches + SHK ask (дефолт)/yes/no/accept-new (автопин), TOFU-промпт сохранён | заявлено — сверить |
| 2.4 renewal-семантика | ❌ byte-exact → легитимный renewal = отказ (→ R5) | ✅ 2026-11-05 — CHANGED + chain CA-valid + SAN → перепин (`s3_cli_kh_replace`, лог «certificate rotated, chain valid»); self-signed ротация — через SSHFP-перепин | — (после сверки) |
| 2.5 SSHFP | ✅ (`checkHostKeySSHFP`) | ✅ 2026-11-05 — `s3_ssh3_sshfp` (`c00139b`, порт sshfp.go 1:1, сырой DNS по UDP), `-o VerifyHostKeyDNS=yes|ask|no`, mismatch → отказ, verified → перепин CHANGED-самоподписанного | — (после сверки) |
| 3.3 keylog в релизе | ок | ✅ 2026-11-05 — keylog-cb в клиентском CTX только при `S3_KEYLOG`; `-keylog`-файл остался у интероп-харнеса | сверить |

Приёмка ssh3-c: ctest 51/51 (release+asan), mingw чисто; e2e `ssh3-c/interop/cert-verify-e2e.sh` — CA-первый-контакт, renewal-перепин, self-signed accept-new, ask non-console, SSHFP mismatch/verified/soften (python-стаб DNS), keylog-гейт. Детали — `ssh3-c/docs/PLAN-CURRENT.md` (Блок 2, B-вер).

## 5. Приоритеты (решение владельца 2026-11-04)

1. **ssh3-c** — критично: единственный якорь клиента — пин; первый контакт не защищён даже CA-сертификатом; план — пункт в `ssh3-c/docs/PLAN-CURRENT.md` (Блок 2). **Закрыто 2026-11-05** (см. §4).
2. **ssh3-go** — средне (удобство, не безопасность): renewal-семантика — пункт в `docs/ROADMAP.local.md` R5.
3. **ssh3-rust** — проверка отложена владельцем; пункт в `ROADMAP.md`.
