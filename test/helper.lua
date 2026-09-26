--- Общие средства проверок клиента каталога.
---
--- Каталог подменяется двойником соединения: он отдаёт байты ответа
--- кусками, как их отдал бы сокет, и помнит, что ему написали. Ответы
--- каталога собираются здесь руками — своей записью BER мимо кодировщика
--- пакета: иначе проверка разбора опиралась бы на тот же код, который
--- проверяет. Подменяются сеть, TLS и часы соединения и стенные часы
--- удостоверения; OpenSSL в этих проверках не нужна вовсе.
---
--- Исходники пакета читаются с диска, а не через `require`: у Tarantool
--- свой загрузчик `.rocks`, он идёт раньше `package.path` и подсунул бы
--- установленную копию пакета, если она есть. Проверки тогда шли бы
--- против вчерашнего кода, а покрытие считалось бы по нему. Зависимости
--- пакета — `tnt-must`, `tnt-clock`, `tnt-external` и `tnt-tls` — берутся
--- из `.rocks` обычным `require`: проверяется этот пакет, а не они.
---
--- Загрузчик исходников в `test/testing/` грузится так же, файлом, и один
--- раз на процесс: второй экземпляр загрузчика не знал бы, что вытеснил
--- первый, и не вернул бы вытесненное на место.
---
--- Проверки берут всё через этот помощник, а не из оснастки напрямую:
--- помощник — единственное, чем файл проверок отличается от того же файла
--- в наборе, где пакет живёт рядом со своими зависимостями.

local fio = require('fio')
local t = require('luatest')

--- Загрузчик исходников: один на процесс.
if package.loaded['tnt.testing.sources'] == nil then
    local chunk, failure = loadfile(fio.abspath('test/testing/sources.lua'))

    if chunk == nil then
        error(('оснастка tnt.testing.sources не читается: %s'):format(tostring(failure)))
    end

    package.loaded['tnt.testing.sources'] = chunk()
end

local sources = package.loaded['tnt.testing.sources']

--- Модули пакета в порядке зависимостей.
local OWN = {
    'tnt.ldap.failure',
    'tnt.ldap.ber',
    'tnt.ldap.filter',
    'tnt.ldap.message',
    'tnt.ldap.link',
    'tnt.ldap.settings',
    'tnt.ldap.directory',
    'tnt.ldap',
}

local helper = {
    --- Модули пакета в порядке зависимостей: имя и путь исходника.
    MODULES = {},
}

for _, name in ipairs(OWN) do
    table.insert(helper.MODULES, { name = name, path = (name:gsub('%.', '/')) .. '.lua' })
end

--- Фасад пакета из исходников.
---
--- Грузится при каждом подключении помощника, то есть раз на файл
--- проверок: состояния у пакета нет, кроме внешних зависимостей, а их
--- проверки возвращают сами (`restore`).
helper.ldap = sources.load(helper.MODULES, 'tnt.ldap')

--- Части той же загрузки, что и фасад.
helper.ber = sources.module('tnt.ldap.ber')
helper.directory = sources.module('tnt.ldap.directory')
helper.failure = sources.module('tnt.ldap.failure')
helper.filter = sources.module('tnt.ldap.filter')
helper.link = sources.module('tnt.ldap.link')
helper.message = sources.module('tnt.ldap.message')
helper.settings = sources.module('tnt.ldap.settings')

--- Миг стенных часов проверок: 2026-09-21, с долей секунды.
helper.NOW = 1790000000.25

--- Каталог обычных настроек.
helper.URL = 'ldaps://ldap.example.org'
helper.WHERE = 'ldaps://ldap.example.org'
helper.BIND_DN = 'cn=reader,dc=example,dc=org'
helper.BIND_PASSWORD = 'reader-secret'
helper.BASE = 'ou=people,dc=example,dc=org'
helper.DN = 'uid=anna,ou=people,dc=example,dc=org'
helper.UUID = '8a14f830-4d31-1041-880b-fb9420c1f5a9'
helper.GROUP = 'cn=operators,ou=groups,dc=example,dc=org'

--- Сверяет, что каждый вызов бросает названный отказ и винит строку
--- вызова в файле проверок, а не внутри пакета.
---
--- Вызов стоит в замыкании первой строкой тела, то есть строкой ниже
--- слова `function`: место броска сверяется с ней целиком — файлом,
--- строкой и текстом.
---@param cases table[] Пары: замыкание с вызовом и текст броска
function helper.assert_blamed(cases)
    for _, case in ipairs(cases) do
        local _, err = pcall(case[1])
        local info = debug.getinfo(case[1], 'S') --[[@as { short_src: string, linedefined: integer }]]

        t.assert_equals(err, ('%s:%d: %s'):format(info.short_src, info.linedefined + 1, case[2]))
    end
end

--- Чтение окружения для настроек живых проверок: порты и каталог
--- сертификатов стенда.
---
--- `tnt-env` приходит из `.rocks`: сам пакет окружения не читает,
--- и его зависимостью он не объявлен — его ставит `make deps`.
---@return table
function helper.stand_env()
    return require('tnt.env')
end

--- Значение мимо проверки типов: проверки нарочно передают не то.
---@param value any
---@return any
function helper.wrong(value)
    return value
end

--- Запись BER руками: тег, длина, содержимое.
---
--- Длина — короткой формой до 127 байтов, дальше — байтами длины
--- старшим вперёд.
---@param tag integer
---@param content string
---@return string
function helper.tlv(tag, content)
    local size = #content

    if size < 128 then
        return string.char(tag, size) .. content
    end

    local bytes = ''

    while size > 0 do
        bytes = string.char(size % 256) .. bytes
        size = math.floor(size / 256)
    end

    return string.char(tag, 0x80 + #bytes) .. bytes .. content
end

--- Целое до 32767 записью BER: `INTEGER` либо с другим тегом.
---@param value integer
---@param tag integer|nil
---@return string
function helper.int(value, tag)
    local content = value > 127 and string.char(math.floor(value / 256), value % 256) or string.char(value)

    return helper.tlv(tag or 0x02, content)
end

--- Октетная строка.
---@param value string
---@return string
function helper.octets(value)
    return helper.tlv(0x04, value)
end

--- Сообщение: номер и операция.
---@param id integer
---@param operation string
---@return string
function helper.envelope(id, operation)
    return helper.tlv(0x30, helper.int(id) .. operation)
end

--- Ответ с итогом: код, пустой DN совпавшей части, пояснение.
---@param id integer
---@param tag integer Тег операции ответа
---@param code integer|nil По умолчанию 0 — успех
---@param diagnostic string|nil
---@return string
function helper.result(id, tag, code, diagnostic)
    local body = helper.int(code or 0, 0x0A) .. helper.octets('') .. helper.octets(diagnostic or '')

    return helper.envelope(id, helper.tlv(tag, body))
end

--- Ответ на привязку.
function helper.bound(id, code, diagnostic)
    return helper.result(id, 0x61, code, diagnostic)
end

--- Конец поиска.
function helper.done(id, code, diagnostic)
    return helper.result(id, 0x65, code, diagnostic)
end

--- Ответ на расширенную операцию.
function helper.extended(id, code, diagnostic)
    return helper.result(id, 0x78, code, diagnostic)
end

--- Запись поиска: DN и атрибуты списком `{ имя, { значения } }`.
---@param id integer
---@param dn string
---@param attributes table[]
---@return string
function helper.entry(id, dn, attributes)
    local list = {}

    for _, attribute in ipairs(attributes) do
        local values = {}

        for _, value in ipairs(attribute[2]) do
            table.insert(values, helper.octets(value))
        end

        table.insert(list, helper.tlv(0x30, helper.octets(attribute[1]) .. helper.tlv(0x31, table.concat(values))))
    end

    return helper.envelope(id, helper.tlv(0x64, helper.octets(dn) .. helper.tlv(0x30, table.concat(list))))
end

--- Ссылка на другой каталог в ответе на поиск.
function helper.reference(id)
    return helper.envelope(id, helper.tlv(0x73, helper.octets('ldap://other.example.org/')))
end

--- Запись Анны: опознаватель, имя, группа.
---@param id integer
---@return string
function helper.anna(id)
    return helper.entry(id, helper.DN, {
        { 'entryUUID', { helper.UUID } },
        { 'cn', { 'Анна Петрова' } },
        { 'memberOf', { helper.GROUP } },
    })
end

--- Привязка, какой её пишет клиент: версия 3, DN, пароль.
---@param id integer
---@param dn string
---@param password string
---@return string
function helper.bind_request(id, dn, password)
    return helper.envelope(id, helper.tlv(0x60, helper.int(3) .. helper.octets(dn) .. helper.tlv(0x80, password)))
end

--- Отвязка.
function helper.unbind_request(id)
    return helper.envelope(id, helper.tlv(0x42, ''))
end

--- Двойник соединения.
---
--- Куски отдаются по одному на чтение и не длиннее просимого: чтение
--- не переходит через границу куска — так проверки ставят границы там,
--- где сокет мог бы их поставить. Кусок-функция зовётся, и отдаётся её
--- ответ: так двойник отвечает концом потока (`''`), отказом
--- (`nil, причина`) и броском. Кончились куски — молчание: `nil`
--- и «сервер молчит».
---@param chunks any[]
---@return table io Сокет либо соединение TLS: `read`, `write`, `close`
function helper.stream(chunks)
    local io = { written = {}, timeouts = {}, closed = 0, chunks = chunks, at = 1, rest = nil }

    function io.read(self, opts, timeout)
        table.insert(self.timeouts, timeout)

        if self.rest == nil or self.rest == '' then
            local chunk = self.chunks[self.at]

            self.at = self.at + 1

            if chunk == nil then
                return nil, 'сервер молчит'
            end

            if type(chunk) == 'function' then
                return chunk()
            end

            self.rest = chunk
        end

        local piece = self.rest:sub(1, opts.chunk)

        self.rest = self.rest:sub(opts.chunk + 1)

        return piece
    end

    function io.write(self, data, timeout)
        table.insert(self.written, data)
        table.insert(self.timeouts, timeout)

        return #data
    end

    function io.close(self)
        self.closed = self.closed + 1
    end

    return io
end

---@class TntLdapTestNet Подменённая сеть одного разговора
---@field plain table Сокет до TLS
---@field secured table|nil Соединение после TLS; пусто — рукопожатие не проходит
---@field connected table[] С чем звали `connect`
---@field wrapped table[] С чем звали `wrap`

--- Часы, которые стоят: остаток срока всегда равен сроку вызова.
local function still()
    return 100
end

--- Подменяет сеть: `connect` отдаёт `plain`, `wrap` — `secured`.
---
--- Часы соединения по умолчанию стоят; проверки срока дают свои.
---@param plain table Двойник сокета до TLS
---@param secured table|nil Двойник после TLS; пусто — `wrap` отказывает
---@param clock table|nil Часы `monotonic` и `scheduler_now`, своё открытие сокета `connect`
---@return TntLdapTestNet
function helper.net(plain, secured, clock)
    local net = { plain = plain, secured = secured, connected = {}, wrapped = {} }
    local hands = clock or {}

    helper.link._set_source({
        connect = function(host, port, timeout)
            table.insert(net.connected, { host = host, port = port, timeout = timeout })

            return plain
        end,
        wrap = function(sock, options)
            table.insert(net.wrapped, { socket = sock, options = options })

            if secured == nil then
                return nil, 'сертификат не принят'
            end

            return secured
        end,
        monotonic = hands.monotonic or still,
        scheduler_now = hands.scheduler_now or still,
    })

    -- Своё открытие сокета — поверх, чтобы часы остались стоять.
    if hands.connect ~= nil then
        helper.link._set_source({
            connect = hands.connect,
            wrap = function()
                return secured
            end,
            monotonic = still,
            scheduler_now = still,
        })
    end

    return net
end

--- Стенные часы удостоверения — на миг проверок.
function helper.wall()
    helper.directory._set_source({
        now = function()
            return helper.NOW
        end,
    })
end

--- Настройки каталога поверх обычных.
---@param overrides table|nil
---@param removed string[]|nil Ключи, которых в настройках быть не должно
---@return table
function helper.options(overrides, removed)
    local options = {
        url = helper.URL,
        bind_dn = helper.BIND_DN,
        bind_password = helper.BIND_PASSWORD,
        base = helper.BASE,
        limiter = false,
    }

    for key, value in pairs(overrides or {}) do
        options[key] = value
    end

    for _, key in ipairs(removed or {}) do
        options[key] = nil
    end

    return options
end

--- Каталог с подменённой сетью: TLS с первого байта, ответы — куски.
---@param chunks any[]
---@param overrides table|nil Настройки поверх обычных
---@param removed string[]|nil Ключи, которых в настройках быть не должно
---@return table directory
---@return TntLdapTestNet net
function helper.connected(chunks, overrides, removed)
    local net = helper.net(helper.stream({}), helper.stream(chunks))

    helper.wall()

    return helper.ldap.new(helper.options(overrides, removed)), net
end

--- Возвращает пакету настоящие сеть и часы.
function helper.restore()
    helper.link._set_source(nil)
    helper.directory._set_source(nil)
end

--- Сверяет отказ: пусто и таблица с родом, текстом и полями каталога.
---
--- Ожидание идёт первым: вызов последним аргументом отдаёт оба значения.
---@param expected table kind, message и, если ждут, code, diagnostic, retry_after
---@param outcome any
---@param err any
function helper.assert_refused(expected, outcome, err)
    t.assert_equals(outcome, nil)
    t.assert_equals({
        kind = err.kind,
        message = err.message,
        code = err.code,
        diagnostic = err.diagnostic,
        retry_after = err.retry_after,
    }, expected)
end

return helper
