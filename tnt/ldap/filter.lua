--- Фильтр поиска: запись строкой по RFC 4515 и её перевод в BER (RFC 4511, §4.5.1).
---
--- Фильтр пишут строкой — `(&(objectClass=person)(uid=anna))`, — потому
--- что так его пишут администраторы каталогов и так он лежит в настройках.
--- Каталог же принимает фильтр записью BER, и строку разбирает клиент.
---
--- **Значение от посетителя — только через `escape`.** В записи строкой
--- `*`, `(`, `)`, `\` и нулевой байт — разметка, и имя `*)(uid=*`,
--- вставленное как есть, превращает поиск одной записи в поиск любой
--- (RFC 4515, §3). `escape` пишет каждый такой байт кодом `\2a`, и разбор
--- возвращает его значением, а не разметкой.
---
--- Разбор строгий: скобки обязательны, пустых списков `(&)` и `(|)` нет,
--- `\` без двух шестнадцатеричных цифр, скобка и нулевой байт внутри
--- значения, пустая часть между звёздочками — отказ. Фильтр пишет
--- программист, и опечатка в нём видна при сборке, а не на входе
--- посетителя, когда поиск молча не нашёл бы никого.

local ber = require('tnt.ldap.ber')

local Module = {}

--- Теги фильтра (RFC 4511, §4.5.1): контекстный класс, у всех, кроме
--- `present`, — составная запись.
local AND = 0xA0
local OR = 0xA1
local NOT = 0xA2
local SUBSTRINGS = 0xA4
local PRESENT = 0x87
local EXTENSIBLE = 0xA9

--- Сравнения по значению: равенство, не меньше, не больше, приблизительно.
local COMPARISONS = { ['='] = 0xA3, ['>='] = 0xA5, ['<='] = 0xA6, ['~='] = 0xA8 }

--- Части подстроки: начало, середина, конец.
local INITIAL = 0x80
local ANY = 0x81
local FINAL = 0x82

--- Части сравнения по правилу: правило, атрибут, значение, признак `dn`.
local RULE = 0x81
local TYPE = 0x82
local MATCH = 0x83
local DN_ATTRIBUTES = 0x84

--- Имя атрибута: имя либо числовой OID и параметры через `;`
--- (RFC 4512, §2.5). Шире стандарта ровно настолько, чтобы не держать
--- две грамматики, и уже его там, где это важно: ни пробела, ни скобки,
--- ни `=`, ни `:`, ни `*`.
local ATTRIBUTE = '^[%w][%w%-%.;]*$'

--- Байты, которые в записи строкой — разметка (RFC 4515, §3).
local SPECIAL = '[%z%(%)%*\\]'

--- Байт кодом `\hh`.
---@param byte string
---@return string
local function coded(byte)
    return ('\\%02x'):format(byte:byte())
end

--- Значение для вставки в фильтр: разметка кодами, остальное как есть.
---
---     filter.escape('*)(uid=*')   --> '\2a\29\28uid=\2a'
---@param value string
---@return string
function Module.escape(value)
    return (value:gsub(SPECIAL, coded))
end

--- Значение из записи строкой: коды `\hh` — байтами.
---@param text string Значение без звёздочек-разметки
---@return string|nil value
---@return string|nil err
local function unescape(text)
    if text:find('[%z%(]') then
        return nil, 'скобка и нулевой байт в значении пишутся кодом: \\28, \\00'
    end

    -- Одиночная `\\` в образце Lua — обычный знак: особый там `%`.
    if text:gsub('\\%x%x', ''):find('\\') then
        return nil, 'после \\ в значении — две шестнадцатеричные цифры'
    end

    return (
        text:gsub('\\(%x%x)', function(hex)
            return string.char(tonumber(hex, 16) --[[@as integer]])
        end)
    )
end

--- Проверенное имя атрибута.
---@param name string
---@return string|nil name
---@return string|nil err
local function attribute(name)
    if not name:find(ATTRIBUTE) then
        return nil, ('«%s» — не имя атрибута'):format(name)
    end

    return name
end

--- Части текста между разделителями, пустые тоже.
---@param text string
---@param separator string Один знак, не особый для образцов Lua
---@return string[]
local function split(text, separator)
    local parts = {}

    for part in (text .. separator):gmatch('([^' .. separator .. ']*)' .. separator) do
        table.insert(parts, part)
    end

    return parts
end

--- Октетная строка BER.
---@param value string
---@return string
local function octets(value)
    return ber.encode(ber.OCTET_STRING, value)
end

--- Подстрока: `(cn=an*na*)` — начало, середины, конец.
---@param name string Имя атрибута
---@param parts string[] Значения между звёздочками, в записи строкой
---@return string|nil encoded
---@return string|nil err
local function substrings(name, parts)
    local encoded = {}

    for index, part in ipairs(parts) do
        local value, err = unescape(part)

        if value == nil then
            return nil, err
        end

        local tag = index == 1 and INITIAL or index == #parts and FINAL or ANY

        -- Пустое начало и пустой конец — это звёздочка с края; пустая
        -- середина — две звёздочки подряд, и такой части нет (RFC 4511, §4.5.1).
        if value ~= '' then
            table.insert(encoded, ber.encode(tag, value))
        elseif tag == ANY then
            return nil, 'две звёздочки подряд: пустой части подстроки нет'
        end
    end

    return ber.encode(SUBSTRINGS, octets(name) .. ber.encode(ber.SEQUENCE, table.concat(encoded)))
end

--- Сравнение по правилу: `(cn:dn:2.5.13.5:=Анна)`, `(:1.2.3:=x)`.
---@param left string Всё до `:=` без последнего двоеточия
---@param value string
---@return string|nil encoded
---@return string|nil err
local function extensible(left, value)
    local parts = split(left, ':')
    local name = table.remove(parts, 1)
    local dn = parts[1] ~= nil and parts[1]:lower() == 'dn'

    if dn then
        table.remove(parts, 1)
    end

    local rule = table.remove(parts, 1)

    if #parts > 0 or rule == '' or (name == '' and rule == nil) then
        return nil, 'сравнение по правилу пишется attr:dn:правило:=значение'
    end

    local content = {}

    if rule ~= nil then
        local checked, err = attribute(rule)

        if checked == nil then
            return nil, err
        end

        table.insert(content, ber.encode(RULE, rule))
    end

    if name ~= '' then
        local checked, err = attribute(name)

        if checked == nil then
            return nil, err
        end

        table.insert(content, ber.encode(TYPE, name))
    end

    table.insert(content, ber.encode(MATCH, value))

    if dn then
        table.insert(content, ber.encode(DN_ATTRIBUTES, '\255'))
    end

    return ber.encode(EXTENSIBLE, table.concat(content))
end

--- Простое условие между скобками: `uid=anna`, `cn=*`, `age>=18`.
---@param body string
---@return string|nil encoded
---@return string|nil err
local function item(body)
    local left, operator, right = body:match('^(.-)([~<>]?=)(.*)$')

    if left == nil then
        return nil, ('в условии «%s» нет сравнения'):format(body)
    end

    ---@cast right string

    local parts = split(right, '*')
    local extended = operator == '=' and left:sub(-1) == ':'

    if #parts > 1 and (operator ~= '=' or extended) then
        return nil,
            'звёздочка-разметка годится только в равенстве, а звёздочка-значение пишется кодом \\2a'
    end

    if extended then
        local value, err = unescape(right)

        if value == nil then
            return nil, err
        end

        return extensible(left:sub(-#left, -2), value)
    end

    local name, wrong = attribute(left)

    if name == nil then
        return nil, wrong
    end

    if #parts == 1 then
        local value, err = unescape(right)

        if value == nil then
            return nil, err
        end

        return ber.encode(COMPARISONS[operator], octets(name) .. octets(value))
    end

    if right == '*' then
        return ber.encode(PRESENT, name)
    end

    return substrings(name, parts)
end

--- Сверяет закрывающую скобку составного условия.
---@param text string
---@param at integer Где она должна стоять
---@param encoded string Условие, если она на месте
---@return string|nil encoded
---@return integer|string after Позиция за скобкой либо текст отказа
local function closed(text, at, encoded)
    if text:sub(at, at) ~= ')' then
        return nil, ('на месте %d ждали «)»'):format(at)
    end

    return encoded, at + 1
end

--- Разбирает фильтр в скобках с позиции `at`.
---@param text string
---@param at integer
---@return string|nil encoded
---@return integer|string after Позиция за скобкой либо текст отказа
local function parse(text, at)
    if text:sub(at, at) ~= '(' then
        return nil, ('на месте %d ждали «(»'):format(at)
    end

    local mark = text:sub(at + 1, at + 1)

    if mark == '&' or mark == '|' then
        local parts = {}
        local next_at = at + 2

        while text:sub(next_at, next_at) == '(' do
            local part, after = parse(text, next_at)

            if part == nil then
                return nil, after
            end

            table.insert(parts, part)
            next_at = after --[[@as integer]]
        end

        if #parts == 0 then
            return nil, ('в «%s» пустой список условий'):format(mark)
        end

        return closed(text, next_at, ber.encode(mark == '&' and AND or OR, table.concat(parts)))
    end

    if mark == '!' then
        local inner, after = parse(text, at + 2)

        if inner == nil then
            return nil, after
        end

        return closed(text, after --[[@as integer]], ber.encode(NOT, inner))
    end

    local close = text:find('%)', at)

    if close == nil then
        return nil, 'нет закрывающей скобки'
    end

    local encoded, err = item(text:sub(at + 1, close - 1))

    if encoded == nil then
        return nil, err --[[@as string]]
    end

    return encoded, close + 1
end

--- Фильтр строкой — в запись BER.
---
---     filter.encode('(&(objectClass=person)(uid=anna))')   --> запись BER
---     filter.encode('(uid=anna')   --> nil, 'фильтр «(uid=anna»: нет закрывающей скобки'
---@param text string
---@return string|nil encoded
---@return string|nil err
function Module.encode(text)
    local encoded, after = parse(text, 1)

    if encoded ~= nil and after ~= #text + 1 then
        encoded, after = nil, ('после фильтра лишнее с места %d'):format(after)
    end

    if encoded == nil then
        return nil, ('фильтр «%s»: %s'):format(text, after)
    end

    return encoded
end

return Module
