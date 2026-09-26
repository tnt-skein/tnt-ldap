--- BER в той мере, в какой на нём говорит LDAP (RFC 4511, §5.1; X.690).
---
--- Запись BER — тег, длина и содержимое. LDAP сужает X.690: длина только
--- определённая, тег однобайтовый, у логического значения «истина» —
--- байт `FF`. Этого подмножества хватает на все сообщения клиента, и его
--- проще держать строгим целиком, чем разбирать лишнее и надеяться,
--- что оно не придёт.
---
--- Разбор строгий, потому что ответ пишет чужая машина: оборванная
--- запись, длина длиннее сообщения, неопределённая длина, многобайтовый
--- тег — отказ текстом, а не бросок и не чтение за край. Глубина
--- вложенности ограничена: запись из одних заголовков «последовательность
--- в последовательности» иначе уводила бы разбор в рекурсию до переполнения
--- стека процесса.

local bit = require('bit')

local Module = {}

--- Теги универсального класса, которые встречаются в LDAP.
Module.BOOLEAN = 0x01
Module.INTEGER = 0x02
Module.OCTET_STRING = 0x04
Module.ENUMERATED = 0x0A
Module.SEQUENCE = 0x30
Module.SET = 0x31

--- Самая глубокая вложенность, которую разбор принимает.
---
--- У сообщений LDAP она пять-шесть уровней: сообщение, операция, список
--- атрибутов, атрибут, набор значений, у элементов управления — ещё два.
Module.MAX_DEPTH = 16

--- Самая длинная запись длины: четыре байта — это уже 4 ГиБ.
local MAX_LENGTH_BYTES = 4

--- Бит составной записи в теге: у неё внутри записи, а не байты.
local CONSTRUCTED = 0x20

--- Длина содержимого в записи BER.
---
--- До 127 байтов — одним байтом, дальше — байт с числом байтов длины
--- и сама длина старшим байтом вперёд (X.690, §8.1.3).
---@param size integer
---@return string
local function length_of(size)
    if size < 0x80 then
        return string.char(size)
    end

    local bytes = {}

    while size > 0 do
        table.insert(bytes, 1, string.char(size % 0x100))
        size = math.floor(size / 0x100)
    end

    return string.char(0x80 + #bytes) .. table.concat(bytes)
end

--- Запись BER: тег, длина, содержимое.
---@param tag integer
---@param content string
---@return string
function Module.encode(tag, content)
    return string.char(tag) .. length_of(#content) .. content
end

--- Целое без знака: номер сообщения, версия, пределы, перечисления.
---
--- Кодирование — дополнительный код наименьшей длины (X.690, §8.3):
--- число со старшим битом первого байта читалось бы отрицательным,
--- и перед ним встаёт нулевой байт.
---@param value integer Не меньше нуля
---@param tag integer|nil Тег; по умолчанию `INTEGER`
---@return string
function Module.integer(value, tag)
    local bytes = {}

    repeat
        table.insert(bytes, 1, string.char(value % 0x100))
        value = math.floor(value / 0x100)
    until value == 0

    local content = table.concat(bytes)

    if content:byte(1) >= 0x80 then
        content = '\0' .. content
    end

    return Module.encode(tag or Module.INTEGER, content)
end

--- Сколько байтов длины идёт следом за первым байтом длины.
---
--- Короткая форма — ноль. Неопределённая длина (`80`) LDAP запрещена
--- (RFC 4511, §5.1), а больше четырёх байтов длины не бывает у сообщения,
--- которое стоит читать: на обоих отказ.
---@param first integer Первый байт длины
---@return integer|nil count
---@return string|nil err
function Module.length_bytes(first)
    if first < 0x80 then
        return 0
    end

    local count = first - 0x80

    if count == 0 then
        return nil,
            'длина BER неопределённая, а LDAP знает только определённую'
    end

    if count > MAX_LENGTH_BYTES then
        return nil, ('длина BER в %d байтах — больше четырёх'):format(count)
    end

    return count
end

--- Заголовок записи с позиции `at`: тег, начало и длина содержимого.
---
--- Содержимое здесь не читается — только проверяется, что заголовок цел.
--- Им же разбирается начало сообщения, пришедшего из сокета: длина
--- известна раньше, чем пришло тело.
---@param data string
---@param at integer
---@return integer|nil tag
---@return integer|string start Начало содержимого либо текст отказа
---@return integer|nil size
function Module.header(data, at)
    -- Двумя вызовами, а не одним `byte(at, at + 1)`: лишний третий байт
    -- того вызова отбрасывался бы молча.
    local tag, first = data:byte(at), data:byte(at + 1)

    if first == nil then
        return nil, 'запись BER оборвана на заголовке'
    end

    if tag % CONSTRUCTED == 0x1F then
        return nil, 'тег BER многобайтовый, а LDAP таких не знает'
    end

    local count, err = Module.length_bytes(first)

    if count == nil then
        return nil, err --[[@as string]]
    end

    local start = at + 2 + count

    if start - 1 > #data then
        return nil, 'запись BER оборвана на длине'
    end

    -- У короткой формы длина — сам первый байт, и цикл не идёт ни разу.
    local size = count == 0 and first or 0

    for index = at + 2, start - 1 do
        size = size * 0x100 + data:byte(index)
    end

    return tag, start, size
end

---@class TntLdapBerNode Запись BER после разбора
---@field tag integer Тег целиком, с классом и битом составной записи
---@field value string|nil Содержимое простой записи
---@field items TntLdapBerNode[]|nil Записи внутри составной

--- Записи BER подряд от `from` до `to` включительно — в список `into`.
---@param data string
---@param from integer
---@param to integer
---@param depth integer Сколько составных записей вокруг
---@param into TntLdapBerNode[]
---@return string|nil err
local function parse(data, from, to, depth, into)
    local at = from

    while at <= to do
        local tag, head, size = Module.header(data, at)

        if tag == nil then
            return head --[[@as string]]
        end

        local start = head --[[@as integer]]
        local stop = start + size --[[@as integer]] - 1

        if stop > to then
            return 'запись BER длиннее того, что её содержит'
        end

        local node = { tag = tag }

        if bit.band(tag, CONSTRUCTED) == 0 then
            node.value = data:sub(start, stop)
        elseif depth == Module.MAX_DEPTH then
            return ('записи BER вложены глубже %d уровней'):format(Module.MAX_DEPTH)
        else
            node.items = {}

            local err = parse(data, start, stop, depth + 1, node.items)

            if err ~= nil then
                return err
            end
        end

        table.insert(into, node)
        at = (stop + 1) --[[@as integer]]
    end
end

--- Разбирает записи BER целиком.
---@param data string
---@return TntLdapBerNode[]|nil nodes
---@return string|nil err
function Module.decode(data)
    local nodes = {}
    local err = parse(data, 1, #data, 0, nodes)

    if err ~= nil then
        return nil, err
    end

    return nodes
end

--- Целое из содержимого записи `INTEGER` либо `ENUMERATED`.
---
--- Знак не разбирается: номера сообщений и коды итога в LDAP
--- неотрицательны (RFC 4511, §4.1.1, §4.1.9), а число со старшим битом,
--- прочитанное без знака, не совпадёт ни с одним нашим номером и ни
--- с одним кодом, которого ждут. Длиннее четырёх байтов номер не бывает.
---@param content string
---@return integer|nil
function Module.to_integer(content)
    if #content == 0 or #content > 4 then
        return nil
    end

    local value = 0

    for index = 1, #content do
        value = value * 0x100 + content:byte(index)
    end

    return value
end

return Module
