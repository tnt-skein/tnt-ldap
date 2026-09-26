--- Настройки клиента каталога: проверка при сборке.
---
--- Негодная настройка — ошибка программиста, и видна она при сборке
--- клиента, а не на первом входе посетителя: бросок на строке вызывающего
--- `ldap.new`. Решения, которые держит проверка:
---
--- * **TLS всегда.** Адрес — `ldaps://` (TLS с первого байта, порт 636)
---   либо `ldap://` (всегда StartTLS, порт 389); открытого разговора
---   у пакета нет, и выключить TLS нечем (RFC 4513, §6.3.1).
--- * **Служебная учётная запись — парой.** DN без пароля ушёл бы простой
---   привязкой без проверки (RFC 4513, §5.1.2), и каталог ответил бы
---   успехом, ничего не проверив; пароль без DN не значит ничего. Без
---   обоих поиск идёт без входа — если каталог его пускает.
--- * **Фильтр — с `{username}` на месте значения.** Он разбирается при
---   сборке как есть, и `{username}` на месте имени атрибута или правила
---   сравнения — промах: имя посетителя встаёт только значением.
--- * **Счёт попыток обязателен**: ограничитель (`consume`) и предел
---   (`by`), либо явное `limiter = false`. Перебор паролей мимо счёта
---   запирал бы настоящих людей в самом каталоге, и забыть о счёте молча
---   нельзя.

local fail = require('tnt.must.fail')
local must = require('tnt.must')

local filter = require('tnt.ldap.filter')

local Module = {}

--- Источник удостоверения по умолчанию.
Module.NAME = 'ldap'

--- Самое длинное имя источника: оно стоит приставкой в ключе счёта
--- попыток и полем `provider` в каждом удостоверении.
Module.MAX_NAME = 64

--- Срок одного вызова по умолчанию, секунд.
Module.TIMEOUT = 5

--- Что подставляется в фильтр вместо имени посетителя.
Module.USERNAME = '{username}'

--- Умолчания поиска записи посетителя.
Module.FILTER = '(uid={username})'
Module.SCOPE = 'sub'
Module.SUBJECT = 'entryUUID'
Module.DISPLAY = 'cn'
Module.ATTRIBUTES = { 'memberOf' }

--- Порт по схеме адреса.
local PORTS = { ldap = 389, ldaps = 636 }

--- Имя источника: по нему ветвятся правила, и регистр развёл бы `LDAP`
--- и `ldap` по разным веткам.
local NAME = '^%l[%l%d_.%-]*$'

--- Описание настроек.
local OPTIONS = {
    name = '?string',
    url = 'not_empty',
    timeout = '?number',
    tls = {
        '?options',
        { verify = '?boolean', ca_file = '?not_empty', ca_path = '?not_empty', sni = '?string' },
    },
    bind_dn = '?not_empty',
    bind_password = '?not_empty',
    base = 'string',
    scope = { '?one_of', { 'base', 'one', 'sub' } },
    filter = '?not_empty',
    subject = '?not_empty',
    display = '?not_empty',
    attributes = { '?array_of', 'not_empty' },
    limiter = '?',
    limit = '?',
}

---@class TntLdapTls Настройки TLS — те же, что у `tnt-tls`
---@field verify boolean|nil Проверять ли сертификат; выключает только `false`
---@field ca_file string|nil Файл доверенных корней вместо системных
---@field ca_path string|nil Каталог доверенных корней вместо системных
---@field sni string|nil Имя для SNI вместо узла

---@class TntLdapOptions Настройки клиента
---@field name string|nil Источник удостоверения; по умолчанию `ldap`
---@field url string `ldaps://узел[:порт]` либо `ldap://узел[:порт]` (StartTLS)
---@field timeout number|nil Срок одного вызова, секунд; по умолчанию 5
---@field tls TntLdapTls|nil Проверка сертификата каталога
---@field bind_dn string|nil DN служебной учётной записи для поиска
---@field bind_password string|nil Её пароль
---@field base string С какой записи искать посетителя
---@field scope string|nil base, one либо sub; по умолчанию sub
---@field filter string|nil Фильтр с `{username}`; по умолчанию `(uid={username})`
---@field subject string|nil Атрибут опознавателя; по умолчанию `entryUUID`
---@field display string|nil Атрибут имени для людей; по умолчанию `cn`
---@field attributes string[]|nil Атрибуты в `claims`; по умолчанию `{ 'memberOf' }`
---@field limiter table|false Ограничитель с `consume(правило)` либо `false` — без счёта
---@field limit table|nil Предел с `by(ключ)`: сколько попыток по имени за окно

---@class TntLdapSettings: TntLdapEndpoint Проверенные настройки: и куда соединяться
---@field name string
---@field timeout number
---@field bind_dn string|nil
---@field bind_password string|nil
---@field base string
---@field scope string
---@field filter string
---@field subject string
---@field display string
---@field attributes string[]
---@field limiter table|nil
---@field limit table|nil

--- Бросает, если значение не такого вида: текст — как у `tnt-must`.
---@param value string
---@param name string Имя настройки в тексте
---@param pattern string
---@param expected string Каким значению быть
---@param level integer Уровень вины, как у `error`: 1 — эта функция
local function shaped(value, name, pattern, expected, level)
    if not value:find(pattern) then
        error(fail.text(name, expected, ('«%s»'):format(value)), level)
    end
end

--- Узел и порт из части адреса: `узел`, `узел:порт`, `[v6]`, `[v6]:порт`.
---@param authority string
---@return string|nil host
---@return string|nil port Цифры порта; пусто — порт не назван
local function authority_of(authority)
    local host, rest = authority:match('^%[([%x:%.]+)%](.*)$')

    if host == nil then
        host, rest = authority:match('^([^:%[%]@]+)(.*)$')
    end

    if host == nil or rest == '' then
        return host
    end

    local port = (rest --[[@as string]]):match('^:(%d+)$')

    return port and host, port
end

--- Разбирает адрес каталога.
---@param url string
---@param level integer Уровень вины, как у `error`: 1 — эта функция
---@return { host: string, port: integer, starttls: boolean, where: string } endpoint Узел, порт, StartTLS и адрес
local function endpoint_of(url, level)
    local scheme, authority, tail = url:match('^(ldaps?)://([^/?#]*)(.*)$')

    if scheme == nil or (tail ~= '' and tail ~= '/') then
        error(
            fail.text(
                'настройки.url',
                'адрес ldaps://узел[:порт] либо ldap://узел[:порт]',
                ('«%s»'):format(url)
            ),
            level
        )
    end

    local host, port = authority_of(authority --[[@as string]])

    if host == nil then
        error(
            ('настройки.url: узел и порт не разобрать в «%s»'):format(authority),
            level
        )
    end

    local number = port and tonumber(port) or PORTS[scheme]

    must.at(level).between(number, 'настройки.url: порт', 1, 65535)

    return {
        host = host,
        port = number --[[@as integer]],
        starttls = scheme == 'ldap',
        where = ('%s://%s'):format(scheme, authority),
    }
end

--- Проверяет фильтр: разбирается ли он и есть ли в нём имя посетителя.
---@param template string
---@param level integer Уровень вины, как у `error`: 1 — эта функция
local function filter_of(template, level)
    -- В `{username}` нет знаков, особых для образцов Lua: ищется как есть.
    if not template:find(Module.USERNAME) then
        error(('настройки.filter: нет %s — искать некого'):format(Module.USERNAME), level)
    end

    local encoded, err = filter.encode(template)

    if encoded == nil then
        error(('настройки.filter: %s'):format(err), level)
    end
end

--- Проверяет пару «ограничитель и предел».
---@param limiter any
---@param limit any
---@param level integer Уровень вины, как у `error`: 1 — эта функция
local function attempts_of(limiter, limit, level)
    if limiter == false then
        if limit ~= nil then
            error(
                'настройки.limit: предел без ограничителя не считается — нужен limiter',
                level
            )
        end

        return
    end

    if type(limiter) ~= 'table' or type(limiter.consume) ~= 'function' then
        local message =
            'настройки.limiter: счёт попыток обязателен — ограничитель tnt-throttle либо false'

        error(message, level)
    end

    if type(limit) ~= 'table' or type(limit.by) ~= 'function' then
        error(
            'настройки.limit: нужен предел tnt-throttle — throttle.per_minute(5) и подобные',
            level
        )
    end
end

--- Проверяет настройки и собирает проверенные.
---@param options TntLdapOptions
---@param level integer Уровень вины, как у `error`: 1 — эта функция
---@return TntLdapSettings
function Module.check(options, level)
    must.at(level).options(options, 'настройки', OPTIONS)

    local blamed = must.at(level)

    local name = options.name or Module.NAME

    shaped(
        name,
        'настройки.name',
        NAME,
        'строчная латиница, цифры, «_», «.» и «-», с буквы',
        level + 1
    )
    blamed.length(name, 'настройки.name', 1, Module.MAX_NAME)

    local endpoint = endpoint_of(options.url, level + 1)
    local timeout = options.timeout or Module.TIMEOUT

    blamed.positive(timeout, 'настройки.timeout')

    if (options.bind_dn == nil) ~= (options.bind_password == nil) then
        error(
            'настройки.bind_dn и bind_password — только парой: DN без пароля каталог пускает без проверки',
            level
        )
    end

    local template = options.filter or Module.FILTER

    filter_of(template, level + 1)
    attempts_of(options.limiter, options.limit, level + 1)

    return {
        name = name,
        where = endpoint.where,
        host = endpoint.host,
        port = endpoint.port,
        starttls = endpoint.starttls,
        tls = table.copy(options.tls or {}),
        timeout = timeout,
        bind_dn = options.bind_dn,
        bind_password = options.bind_password,
        base = options.base,
        scope = options.scope or Module.SCOPE,
        filter = template,
        subject = options.subject or Module.SUBJECT,
        display = options.display or Module.DISPLAY,
        attributes = table.copy(options.attributes or Module.ATTRIBUTES),
        limiter = options.limiter or nil,
        limit = options.limit,
    }
end

return Module
