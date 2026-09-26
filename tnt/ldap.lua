--- Клиент каталога LDAP: вход паролем с удостоверением и поиск записей.
---
---     local ldap = require('tnt.ldap')
---
---     local directory = ldap.new({
---         url = 'ldaps://ldap.example.org',
---         bind_dn = 'cn=reader,dc=example,dc=org',
---         bind_password = secret,
---         base = 'ou=people,dc=example,dc=org',
---         filter = '(&(objectClass=inetOrgPerson)(uid={username}))',
---         limiter = limiter,              -- счёт попыток: consume и by
---         limit = per_minute(5),
---     })
---
---     local assertion, err = directory:authenticate(username, password)
---
--- LDAPv3 (RFC 4511) поверх сокета Tarantool и `tnt-tls`: TLS всегда —
--- `ldaps://` с первого байта либо `ldap://` со StartTLS, — простая
--- привязка паролем, поиск с фильтром RFC 4515. Вход — «найти, затем
--- войти»: пустой пароль и счёт попыток — до каталога, имя в фильтре
--- экранировано, `subject` — `entryUUID` записи, а не DN. Личности пакет
--- не знает: он отдаёт удостоверение, а учётную запись по нему находит
--- само приложение.
---
--- Отказ — пара `nil, err` с родом (`tnt.ldap.failure`), негодный
--- аргумент — бросок на строке вызывающего. Подробно — `docs/ldap.md`.

local directory = require('tnt.ldap.directory')
local failure = require('tnt.ldap.failure')
local filter = require('tnt.ldap.filter')
local link = require('tnt.ldap.link')

local Module = {}

Module.new = directory.new

--- Значение для вставки в фильтр строкой: разметка — кодами `\hh`.
Module.escape = filter.escape

--- Самое длинное сообщение каталога, байтов.
Module.MAX_MESSAGE = link.MAX_MESSAGE

--- Роды отказа.
Module.INVALID = failure.INVALID
Module.THROTTLED = failure.THROTTLED
Module.UNAVAILABLE = failure.UNAVAILABLE
Module.REJECTED = failure.REJECTED
Module.MALFORMED = failure.MALFORMED

return Module
