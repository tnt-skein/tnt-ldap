--- Соединение с каталогом: открыть под TLS, обменяться сообщениями, закрыть.
---
--- Здесь всё, что ходит в сеть. Соединение живёт один вызов: `open`,
--- несколько обменов, `close`. Пула нет нарочно: вход паролем меняет
--- того, от чьего имени идёт соединение, и соединение после чужого входа
--- пришлось бы перепривязывать к служебной учётной записи, а входы
--- редки, и рукопожатие на каждый стоит миллисекунды.
---
--- **TLS всегда.** Простая привязка несёт пароль открытым текстом
--- (RFC 4513, §6.3.1), поэтому открытого соединения у пакета нет вовсе:
--- `ldaps://` поднимает TLS с первого байта, `ldap://` — всегда StartTLS
--- (RFC 4511, §4.14), и отказ каталога перейти на TLS — отказ соединения,
--- а не разговор открытым текстом.
---
--- **Один срок на вызов.** Миг срока отмечается настоящими монотонными
--- часами, а остаток каждого ожидания считается от времени планировщика:
--- сокет и `tnt-tls` отсчитывают свои сроки от него же. Кончился срок —
--- отказ `unavailable`, и ни одно ожидание не начинается с нулевым
--- остатком.
---
--- **Сообщение не длиннее `MAX_MESSAGE`.** Длина приходит от каталога
--- в заголовке раньше тела, и сообщение длиннее предела не читается: иначе
--- чужая машина одной записью длины заставила бы узел копить гигабайты.

local clock = require('tnt.clock')
local external = require('tnt.external')
local socket = require('socket')
local tls = require('tnt.tls')

local ber = require('tnt.ldap.ber')
local failure = require('tnt.ldap.failure')
local message = require('tnt.ldap.message')

local Module = {}

--- Самое длинное сообщение каталога, байтов.
---
--- Запись учётной записи с тысячей групп в `memberOf` — около сотни
--- килобайтов; мегабайт — с запасом на порядок.
Module.MAX_MESSAGE = 1024 * 1024

--- Сколько ждать прощания, секунд: отвязка вежливость, а не дело вызова.
local FAREWELL = 1

--- Номер уведомления без запроса (RFC 4511, §4.4): им каталог говорит,
--- что сейчас закроет соединение.
local NOTICE = 0

--- Внешние зависимости: сеть, TLS и часы срока.
local source = external.install(Module, {
    connect = socket.tcp_connect,
    wrap = tls.wrap,
    monotonic = clock.monotonic,
    scheduler_now = clock.scheduler_now,
})

---@class TntLdapIo Сокет либо соединение TLS: чтение и запись со сроком
---@field read fun(self: TntLdapIo, opts: table, timeout: number): string|nil, string|nil
---@field write fun(self: TntLdapIo, data: string, timeout: number): any, string|nil
---@field close fun(self: TntLdapIo)

---@class TntLdapLink Соединение одного вызова
---@field io TntLdapIo Чем читать и писать
---@field where string Каталог для текста отказа: `ldaps://узел:порт`
---@field next_id integer Номер следующего сообщения

---@class TntLdapEndpoint Куда соединяться
---@field where string Адрес каталога для текста отказа
---@field host string Узел
---@field port integer Порт
---@field starttls boolean Переходить ли на TLS просьбой, а не с первого байта
---@field tls table Настройки `tnt-tls`: verify, ca_file, ca_path, sni

--- Миг срока через `timeout` секунд — по настоящим часам.
---@param timeout number
---@return number
function Module.deadline(timeout)
    return source().monotonic() + timeout
end

--- Отказ `unavailable` с адресом каталога впереди.
---@param where string
---@param text string
---@return nil
---@return TntLdapFailure
local function unavailable(where, text)
    return failure.refuse(failure.UNAVAILABLE, ('каталог %s: %s'):format(where, text))
end

--- Остаток срока либо отказ по сроку.
---
--- Ожидание с нулевым остатком не начинается вовсе: сокет понял бы ноль
--- как «не ждать», а `tnt-tls` — как негодный срок.
---@param where string
---@param deadline number
---@return number|nil left
---@return TntLdapFailure|nil err
function Module.remaining(where, deadline)
    -- Остаток — от времени планировщика: от него же отсчитают свой срок
    -- сокет и `tnt-tls`.
    local left = deadline - source().scheduler_now()

    if left <= 0 then
        return unavailable(where, 'не ответил за срок вызова')
    end

    return left
end

--- Отказ по сроку либо по обрыву — решают часы, а не слова сокета.
---
--- Сокет и TLS называют истёкший срок каждый по-своему, а встроенный
--- сокет по сроку не называет ничего; надёжнее спросить часы.
---@param link TntLdapLink
---@param deadline number
---@param why any Что сказал сокет
---@return nil
---@return TntLdapFailure
local function broken(link, deadline, why)
    local _, late = Module.remaining(link.where, deadline)

    if late ~= nil then
        return nil, late
    end

    return unavailable(
        link.where,
        ('соединение оборвалось: %s'):format(
            tostring(why or 'сокет не назвал причины')
        )
    )
end

--- Пишет сообщение целиком.
---@param link TntLdapLink
---@param data string
---@param deadline number
---@return boolean|nil sent
---@return TntLdapFailure|nil err
function Module.send(link, data, deadline)
    local left, late = Module.remaining(link.where, deadline)

    if left == nil then
        return nil, late
    end

    local io = link.io
    -- Под pcall: сокет, закрытый соседом, бросает, а не отвечает.
    local ok, written, why = pcall(io.write, io, data, left)

    if not (ok and written) then
        return broken(link, deadline, ok and why or written)
    end

    return true
end

--- Читает ровно `size` байтов.
---@param link TntLdapLink
---@param size integer
---@param deadline number
---@return string|nil data
---@return TntLdapFailure|nil err
local function read_exact(link, size, deadline)
    local parts, got = {}, 0
    local io = link.io

    while got < size do
        local left, late = Module.remaining(link.where, deadline)

        if left == nil then
            return nil, late
        end

        local ok, piece, why = pcall(io.read, io, { chunk = size - got }, left)

        if not (ok and piece) then
            return broken(link, deadline, ok and why or piece)
        end

        if piece == '' then
            return unavailable(link.where, 'закрыл соединение посреди ответа')
        end

        table.insert(parts, piece)
        got = got + #piece
    end

    return table.concat(parts)
end

--- Отказ `malformed`: каталог ответил не по протоколу.
---@param link TntLdapLink
---@param text string
---@return nil
---@return TntLdapFailure
local function malformed(link, text)
    return failure.refuse(
        failure.MALFORMED,
        ('каталог %s ответил не по протоколу: %s'):format(link.where, text)
    )
end

--- Читает одно сообщение: заголовок, длину, тело.
---
--- Уведомление без запроса (номер 0) — отказ `unavailable` с пояснением
--- каталога: так он говорит, что закрывает соединение (RFC 4511, §4.4.1).
---@param link TntLdapLink
---@param deadline number
---@return TntLdapMessage|nil message
---@return TntLdapFailure|nil err
function Module.receive(link, deadline)
    local head, err = read_exact(link, 2, deadline)

    if head == nil then
        return nil, err
    end

    -- Сообщение LDAP — всегда последовательность (RFC 4511, §4.1.1): иной
    -- тег, многобайтовый в том числе, — не наше сообщение, и его длине
    -- верить незачем.
    if head:byte(1) ~= ber.SEQUENCE then
        return malformed(
            link,
            ('сообщение начинается тегом 0x%02X, а не последовательностью'):format(
                head:byte(1)
            )
        )
    end

    local count, wrong = ber.length_bytes(head:byte(2))

    if count == nil then
        return malformed(link, wrong --[[@as string]])
    end

    local more, lost = read_exact(link, count, deadline)

    if more == nil then
        return nil, lost
    end

    -- Заголовок уже цел: тег, длина и число её байтов сверены выше.
    local _, _, size = ber.header(head .. more, 1)

    if size > Module.MAX_MESSAGE then
        return malformed(
            link,
            ('сообщение в %d байтов — больше предела %d'):format(
                size,
                Module.MAX_MESSAGE
            )
        )
    end

    local body, cut = read_exact(link, size --[[@as integer]], deadline)

    if body == nil then
        return nil, cut
    end

    local answer, bad = message.decode(head .. more .. body)

    if answer == nil then
        return malformed(link, bad --[[@as string]])
    end

    if answer.id == NOTICE then
        return unavailable(
            link.where,
            ('закрывает соединение: %s'):format(tostring(answer.diagnostic))
        )
    end

    return answer
end

--- Отправляет запрос и отдаёт номер, под которым он ушёл.
---@param link TntLdapLink
---@param build fun(id: integer): string Сборка сообщения по номеру
---@param deadline number
---@return integer|nil id
---@return TntLdapFailure|nil err
function Module.request(link, build, deadline)
    local id = link.next_id

    link.next_id = id + 1

    local sent, err = Module.send(link, build(id), deadline)

    if not sent then
        return nil, err
    end

    return id
end

--- Ответ на запрос с номером `id` и тегом `tag`.
---
--- Каталог отвечает на каждый запрос по порядку, а запрос у клиента
--- в полёте всегда один: сообщение с чужим номером или чужой операцией —
--- ответ не по протоколу.
---@param link TntLdapLink
---@param id integer
---@param tags table<integer, boolean> Какие операции годятся в ответ
---@param deadline number
---@return TntLdapMessage|nil message
---@return TntLdapFailure|nil err
function Module.answer(link, id, tags, deadline)
    local answer, err = Module.receive(link, deadline)

    if answer == nil then
        return nil, err
    end

    if answer.id ~= id or not tags[answer.tag] then
        local text = ('ждали ответа на сообщение %d, а пришло %d с тегом 0x%02X'):format(
            id,
            answer.id,
            answer.tag
        )

        return malformed(link, text)
    end

    return answer
end

--- Закрывает соединение: отвязка и закрытие, чем бы они ни кончились.
---@param link TntLdapLink
function Module.close(link)
    local io = link.io

    pcall(io.write, io, message.unbind(link.next_id), FAREWELL)
    pcall(io.close, io)
end

--- Просит каталог перейти на TLS.
---@param link TntLdapLink
---@param deadline number
---@return boolean|nil agreed
---@return TntLdapFailure|nil err
local function starttls(link, deadline)
    local id, err = Module.request(link, message.starttls, deadline)

    if id == nil then
        return nil, err
    end

    local answer, lost = Module.answer(link, id, { [message.EXTENDED_RESPONSE] = true }, deadline)

    if answer == nil then
        return nil, lost
    end

    if answer.code ~= 0 then
        return failure.result(answer, ('каталог %s не перешёл на TLS'):format(link.where))
    end

    return true
end

--- Закрывает сокет, который не стал соединением, и отдаёт отказ.
---@param plain TntLdapIo
---@param err TntLdapFailure
---@return nil
---@return TntLdapFailure
local function abandon(plain, err)
    pcall(plain.close, plain)

    return nil, err
end

--- Открывает соединение и поднимает TLS.
---
--- При отказе всё открытое закрыто: и сокет, и начатый TLS.
---@param endpoint TntLdapEndpoint
---@param deadline number
---@return TntLdapLink|nil link
---@return TntLdapFailure|nil err
function Module.open(endpoint, deadline)
    local where = endpoint.where
    local left, late = Module.remaining(where, deadline)

    if left == nil then
        return nil, late
    end

    local connected, plain, why = pcall(source().connect, endpoint.host, endpoint.port, left)

    if not (connected and plain) then
        return unavailable(
            where,
            ('соединение не открылось: %s'):format(tostring(connected and why or plain))
        )
    end

    ---@type TntLdapLink
    local link = { io = plain, where = where, next_id = 1 }

    if endpoint.starttls then
        local agreed, refusal = starttls(link, deadline)

        if not agreed then
            return abandon(plain, refusal --[[@as TntLdapFailure]])
        end
    end

    local rest, expired = Module.remaining(where, deadline)

    if rest == nil then
        return abandon(plain, expired --[[@as TntLdapFailure]])
    end

    local options = table.copy(endpoint.tls)

    options.host = endpoint.host
    options.timeout = rest

    local secured, err = source().wrap(plain, options)

    if secured == nil then
        local _, refused =
            unavailable(where, ('рукопожатие TLS не прошло: %s'):format(tostring(err)))

        return abandon(plain, refused)
    end

    link.io = secured

    return link
end

return Module
