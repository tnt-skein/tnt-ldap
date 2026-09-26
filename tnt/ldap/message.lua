--- Сообщения LDAP: запросы клиента и разбор ответов каталога (RFC 4511, §4).
---
--- Клиенту нужны пять операций: простая привязка (вход паролем), поиск,
--- отвязка, переход на TLS (StartTLS, RFC 4511, §4.14) и чтение ответов
--- на них. Прочих операций пакет не шлёт — изменения каталога, сравнения,
--- переименования, — а сообщение, которого он не шлёт и не ждёт, в ответе —
--- отказ разбора.
---
--- Ответ разбирается в плоскую таблицу — номер, тег операции и то, что
--- у этой операции есть: итог с кодом и пояснением, запись поиска с DN
--- и атрибутами. Вид каждой записи сверяется: ответ пишет чужая машина,
--- и запись не того вида — отказ текстом, а не бросок на обращении
--- к полю, которого нет.

local ber = require('tnt.ldap.ber')

local Module = {}

--- Теги операций (RFC 4511, §4.2–§4.14): класс приложения.
Module.BIND_RESPONSE = 0x61
Module.SEARCH_ENTRY = 0x64
Module.SEARCH_DONE = 0x65
Module.SEARCH_REFERENCE = 0x73
Module.EXTENDED_RESPONSE = 0x78

--- Запросы, которые шлёт клиент.
local BIND_REQUEST = 0x60
local UNBIND_REQUEST = 0x42
local SEARCH_REQUEST = 0x63
local EXTENDED_REQUEST = 0x77

--- Простая привязка паролем: `[0]` в выборе способа входа.
local SIMPLE = 0x80

--- Имя расширенной операции: `[0]` в запросе.
local REQUEST_NAME = 0x80

--- Версия протокола: LDAPv3.
local VERSION = 3

--- Переход на TLS (RFC 4511, §4.14.1).
Module.STARTTLS = '1.3.6.1.4.1.1466.20037'

--- Область поиска по имени: сама запись, её дети, всё поддерево.
Module.SCOPES = { base = 0, one = 1, sub = 2 }

--- Октетная строка BER.
---@param value string
---@return string
local function octets(value)
    return ber.encode(ber.OCTET_STRING, value)
end

--- Конверт сообщения: номер и операция.
---
--- Элементов управления (`controls`) клиент не шлёт: ни одна из пяти его
--- операций их не требует.
---@param id integer
---@param operation string
---@return string
local function envelope(id, operation)
    return ber.encode(ber.SEQUENCE, ber.integer(id) .. operation)
end

--- Простая привязка: вход по DN и паролю (RFC 4511, §4.2).
---@param id integer Номер сообщения
---@param dn string
---@param password string
---@return string
function Module.bind(id, dn, password)
    return envelope(id, ber.encode(BIND_REQUEST, ber.integer(VERSION) .. octets(dn) .. ber.encode(SIMPLE, password)))
end

--- Отвязка: вежливое прощание перед закрытием (RFC 4511, §4.3).
---@param id integer
---@return string
function Module.unbind(id)
    return envelope(id, ber.encode(UNBIND_REQUEST, ''))
end

--- Просьба перейти на TLS.
---@param id integer
---@return string
function Module.starttls(id)
    return envelope(id, ber.encode(EXTENDED_REQUEST, ber.encode(REQUEST_NAME, Module.STARTTLS)))
end

---@class TntLdapSearchRequest Поиск в том виде, в каком он уходит
---@field base string С какой записи искать
---@field scope string base, one либо sub
---@field filter string Фильтр записью BER (`tnt.ldap.filter`)
---@field attributes string[] Какие атрибуты вернуть; пусто — все обычные
---@field size_limit integer Сколько записей самое большее
---@field time_limit integer|nil Сколько секунд самое большее искать каталогу; назначает срок вызова

--- Поиск (RFC 4511, §4.5.1).
---
--- Псевдонимы не раскрываются (`neverDerefAliases`): запись-псевдоним
--- уводила бы вход в другую ветку каталога, и найденный по имени
--- оказывался бы не там, где его искали.
---@param id integer
---@param request TntLdapSearchRequest
---@return string
function Module.search(id, request)
    local attributes = {}

    for _, name in ipairs(request.attributes) do
        table.insert(attributes, octets(name))
    end

    local body = table.concat({
        octets(request.base),
        ber.integer(Module.SCOPES[request.scope] --[[@as integer]], ber.ENUMERATED),
        ber.integer(0, ber.ENUMERATED),
        ber.integer(request.size_limit),
        ber.integer(request.time_limit --[[@as integer]]),
        ber.encode(ber.BOOLEAN, '\0'),
        request.filter,
        ber.encode(ber.SEQUENCE, table.concat(attributes)),
    })

    return envelope(id, ber.encode(SEARCH_REQUEST, body))
end

---@class TntLdapAttribute Атрибут записи
---@field type string Имя, как его назвал каталог
---@field values string[] Значения по порядку

---@class TntLdapMessage Ответ каталога
---@field id integer Номер сообщения; 0 — уведомление без запроса
---@field tag integer Тег операции
---@field code integer|nil Код итога у ответов с итогом
---@field diagnostic string|nil Пояснение каталога у ответов с итогом
---@field dn string|nil DN записи поиска
---@field attributes TntLdapAttribute[]|nil Атрибуты записи поиска

--- Запись внутри составной по месту, если у неё ожидаемый тег.
---@param node TntLdapBerNode Составная запись
---@param index integer
---@param tag integer
---@return TntLdapBerNode|nil
local function child(node, index, tag)
    local found = (node.items --[[@as TntLdapBerNode[] ]])[index]

    if found ~= nil and found.tag == tag then
        return found
    end
end

--- Итог операции (RFC 4511, §4.1.9): код, DN совпавшей части, пояснение.
---@param operation TntLdapBerNode
---@param message TntLdapMessage
---@return TntLdapMessage|nil
local function result(operation, message)
    local code = child(operation, 1, ber.ENUMERATED)
    local matched = child(operation, 2, ber.OCTET_STRING)
    local diagnostic = child(operation, 3, ber.OCTET_STRING)

    if code == nil or matched == nil or diagnostic == nil then
        return nil
    end

    message.code = ber.to_integer(code.value --[[@as string]])
    message.diagnostic = diagnostic.value

    return message.code ~= nil and message or nil
end

--- Запись поиска (RFC 4511, §4.5.2): DN и атрибуты со значениями.
---@param operation TntLdapBerNode
---@param message TntLdapMessage
---@return TntLdapMessage|nil
local function entry(operation, message)
    local dn = child(operation, 1, ber.OCTET_STRING)
    local list = child(operation, 2, ber.SEQUENCE)

    if dn == nil or list == nil then
        return nil
    end

    message.dn = dn.value
    message.attributes = {}

    for index in
        ipairs(list.items --[[@as TntLdapBerNode[] ]])
    do
        local attribute = child(list, index, ber.SEQUENCE)
        local name = attribute and child(attribute, 1, ber.OCTET_STRING)
        local set = attribute and child(attribute, 2, ber.SET)

        if name == nil or set == nil then
            return nil
        end

        local values = {}

        for at in
            ipairs(set.items --[[@as TntLdapBerNode[] ]])
        do
            local value = child(set, at, ber.OCTET_STRING)

            if value == nil then
                return nil
            end

            table.insert(values, value.value)
        end

        table.insert(message.attributes, { type = name.value, values = values })
    end

    return message
end

--- Как разбирается каждая операция ответа.
local READERS = {
    [Module.BIND_RESPONSE] = result,
    [Module.SEARCH_DONE] = result,
    [Module.EXTENDED_RESPONSE] = result,
    [Module.SEARCH_ENTRY] = entry,
    -- Ссылка на другой каталог: клиент по ним не ходит, и содержимое
    -- ему не нужно — важно только, что это она.
    [Module.SEARCH_REFERENCE] = function(_, message)
        return message
    end,
}

--- Разбирает сообщение каталога целиком.
---@param raw string Сообщение: запись BER от тега до конца содержимого
---@return TntLdapMessage|nil message
---@return string|nil err
function Module.decode(raw)
    local nodes, err = ber.decode(raw)

    if nodes == nil then
        return nil, err
    end

    -- Сообщение из сокета — одна запись с непустым заголовком, и разбор,
    -- не отказавший, отдаёт её первой.
    local outer = nodes[1] --[[@as TntLdapBerNode]]
    local id = outer.tag == ber.SEQUENCE and child(outer, 1, ber.INTEGER)
    local operation = id and (outer.items --[[@as TntLdapBerNode[] ]])[2]
    local read = operation and READERS[operation.tag]
    local found = operation --[[@as TntLdapBerNode]]
    local message = read
        and read(found, {
            id = ber.to_integer((id --[[@as TntLdapBerNode]]).value --[[@as string]]),
            tag = found.tag,
        }) --[[@as TntLdapMessage|nil]]

    if not message or message.id == nil then
        return nil, 'сообщение каталога не по RFC 4511'
    end

    return message
end

return Module
