# tnt-ldap

Клиент каталога LDAP для Tarantool: вход паролем с удостоверением и поиск
записей. LDAPv3 (RFC 4511) поверх сокета Tarantool — свой BER, фильтр
строкой по RFC 4515, TLS всегда: `ldaps://` с первого байта либо
`ldap://` со StartTLS. Всё, что пришло от каталога негодным, — отказ парой
с родом.

```lua
local ldap = require('tnt.ldap')

local directory = ldap.new({
    url = 'ldaps://ldap.example.org',
    bind_dn = 'cn=readonly,dc=example,dc=org',
    bind_password = os.getenv('LDAP_READER_PASSWORD'),
    base = 'ou=people,dc=example,dc=org',
    limiter = limiter,           -- счёт попыток: consume и by, см. документ
    limit = per_minute(5),
})

local assertion, err = directory:authenticate('anna', 'anna-secret')
--> { provider = 'ldap', subject = 'f2e3b24a-…', name = 'Анна Петрова', methods = { 'pwd' },
-->   authenticated_at = …, claims = { dn = 'uid=anna,ou=people,dc=example,dc=org', memberOf = { … } } }
```

Зависимости: [`tnt-tls`](https://github.com/tnt-skein/tnt-tls) (шифрование),
[`tnt-clock`](https://github.com/tnt-skein/tnt-clock) (часы срока и миг
входа), [`tnt-external`](https://github.com/tnt-skein/tnt-external) (подмена
сети и часов в проверках) и [`tnt-must`](https://github.com/tnt-skein/tnt-must)
(проверки аргументов).

## Зачем

Готового клиента LDAP для Tarantool Community Edition нет, а обёртка над
системной `libldap` ждала бы сети в потоке событий, и узел на это время
стоял бы целиком. Пакет говорит LDAPv3 сам и ждёт сеть файбером. Вход
паролем — «найти, затем войти»: служебная учётная запись ищет запись
посетителя, а пароль проверяет привязка по найденному DN. Каждое решение
закрывает свою дверь:

- **Пустой пароль — отказ до каталога.** Привязка с DN и пустым паролем —
  привязка без проверки (RFC 4513, §5.1.2), и каталог ответил бы успехом.
- **Имя в фильтре экранировано** (RFC 4515, §3): `*)(uid=*` не превращает
  поиск одной записи в поиск любой.
- **TLS всегда**: простая привязка несёт пароль открытым текстом, и открытого
  разговора у пакета нет вовсе.
- **`subject` — `entryUUID` записи** (у Active Directory — `objectGUID`),
  а не DN: DN меняется при переносе записи в другое подразделение.
- **Счёт попыток — до каталога**, иначе перебор паролей запирал бы
  настоящих людей в самом каталоге. Ограничитель приходит настройкой.
- **Неизвестное имя тоже проверяет пароль** — привязкой к записи, которой
  нет: число обменов у обоих отказов одно, и слово одно — «неверное имя
  или пароль».

## Установка

```sh
tt rocks install tnt-ldap --server=https://tnt-skein.github.io/rocks
```

Или из исходников:

```sh
git clone https://github.com/tnt-skein/tnt-ldap.git
cd tnt-ldap && tt rocks make
```

## Как пользоваться

| Действие | Что делает |
|---|---|
| `ldap.new(настройки)` | клиент каталога; в сеть не ходит, промах в настройках — бросок |
| `каталог:authenticate(имя, пароль)` | вход паролем: удостоверение либо `nil, err` |
| `каталог:search({ base, filter, scope, attributes, size_limit })` | записи от имени служебной учётной записи либо `nil, err` |
| `ldap.escape(значение)` | значение для вставки в фильтр строкой |

Отказ — таблица с родом `kind` (`invalid`, `throttled`, `unavailable`,
`rejected`, `malformed`), текстом `message` и тем, что ответил каталог,
в полях `code` и `diagnostic`:

```lua
local assertion, err = directory:authenticate('anna', 'wrong')
--> nil, неверное имя или пароль
err.kind, err.code
--> invalid, 49

directory:search({
    base = 'ou=groups,dc=example,dc=org',
    filter = '(uniqueMember=' .. ldap.escape('uid=anna,ou=people,dc=example,dc=org') .. ')',
    attributes = { 'cn' },
})
--> { { dn = 'cn=operators,ou=groups,dc=example,dc=org', attributes = { cn = { 'operators' } } } }
```

## Проверки

```sh
make deps          # luatest, luacheck, luacov с cluacov, зависимости пакета и tnt-env в .rocks
make check         # форматирование, линт, проверки, покрытие с порогом 100 %
make mutants-all   # мутационное тестирование утилитой tnt-mutants из PATH, порог 100 % убитых
make ldap-up       # OpenLDAP в докере для живых проверок; make ldap-down гасит
```

Покрытие строк — 100 %, убитых мутантов — 100 % (114 проверок, из них
8 живых; 925 мутантов в семи модулях; в фасаде мутировать нечего).
Каталог в проверках — двойник соединения, который отдаёт ответ кусками,
как сокет, и помнит, что ему написали: разговор сверяется байт в байт.
Живые проверки идут против OpenLDAP и без него пропускаются.

## Документ

Полное описание с обоснованием решений: [docs/ldap.md](docs/ldap.md).

## Лицензия

MIT.
