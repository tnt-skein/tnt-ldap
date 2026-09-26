--- Проверки соединения: TLS с первого байта и StartTLS, срок, чтение
--- сообщения кусками, обрывы, уведомление о закрытии, прощание.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.link')

local link = helper.link
local stream = helper.stream

--- Куда соединяться: `ldaps://` либо `ldap://` со StartTLS.
local function endpoint(starttls)
    return {
        where = starttls and 'ldap://ldap.example.org' or helper.WHERE,
        host = 'ldap.example.org',
        port = starttls and 389 or 636,
        starttls = starttls,
        tls = { verify = false, ca_file = '/etc/ssl/own.pem' },
    }
end

--- Соединение поверх двойника, как после `open`.
local function over(io)
    return { io = io, where = helper.WHERE, next_id = 1 }
end

--- Отказ `unavailable` с адресом каталога.
local function unavailable(text, where)
    return { kind = 'unavailable', message = ('каталог %s: %s'):format(where or helper.WHERE, text) }
end

--- Часы планировщика: каждый вопрос — на шаг позже.
local function ticking(start, step)
    local now = start - step

    return function()
        now = now + step

        return now
    end
end

g.after_each(helper.restore)

g.test_deadline_is_measured_by_real_clock_and_left_by_the_scheduler = function()
    helper.net(stream({}), stream({}), {
        monotonic = function()
            return 50
        end,
        scheduler_now = function()
            return 48
        end,
    })

    t.assert_equals(link.deadline(5), 55)
    t.assert_equals(link.remaining(helper.WHERE, 55), 7)
    t.assert_equals(link.remaining(helper.WHERE, 48.5), 0.5)
    helper.assert_refused(
        unavailable('не ответил за срок вызова'),
        link.remaining(helper.WHERE, 47)
    )
    helper.assert_refused(
        unavailable('не ответил за срок вызова'),
        link.remaining(helper.WHERE, 48)
    )
end

g.test_ldaps_raises_tls_from_the_first_byte = function()
    local secured = stream({})
    local net = helper.net(stream({}), secured)
    local opened = link.open(endpoint(false), 105)

    t.assert_equals(opened, { io = secured, where = helper.WHERE, next_id = 1 })
    t.assert_equals(net.connected, { { host = 'ldap.example.org', port = 636, timeout = 5 } })
    t.assert_equals(net.wrapped, {
        {
            socket = net.plain,
            options = { host = 'ldap.example.org', timeout = 5, verify = false, ca_file = '/etc/ssl/own.pem' },
        },
    })
    t.assert_equals(net.plain.written, {})
end

g.test_ldap_asks_for_tls_first = function()
    local plain = stream({ helper.extended(1) })
    local secured = stream({})
    local net = helper.net(plain, secured)
    local opened = link.open(endpoint(true), 105)

    t.assert_equals(opened, { io = secured, where = 'ldap://ldap.example.org', next_id = 2 })
    t.assert_equals(plain.written, { helper.envelope(1, helper.tlv(0x77, helper.tlv(0x80, '1.3.6.1.4.1.1466.20037'))) })
    t.assert_equals(net.connected[1].port, 389)
    t.assert_equals(#net.wrapped, 1)
    t.assert_equals(plain.closed, 0)
end

g.test_a_refused_starttls_closes_the_socket = function()
    local plain = stream({ helper.extended(1, 2, 'unsupported extended operation') })
    local net = helper.net(plain, stream({}))

    helper.assert_refused({
        kind = 'rejected',
        message = 'каталог ldap://ldap.example.org не перешёл на TLS: код 2: unsupported extended operation',
        code = 2,
        diagnostic = 'unsupported extended operation',
    }, link.open(endpoint(true), 105))
    t.assert_equals(plain.closed, 1)
    t.assert_equals(net.wrapped, {})
end

g.test_a_busy_directory_is_unavailable_for_starttls = function()
    helper.net(stream({ helper.extended(1, 51, 'busy') }), stream({}))

    local _, err = link.open(endpoint(true), 105)

    t.assert_equals(err.kind, 'unavailable')
end

g.test_a_silent_directory_breaks_starttls = function()
    local plain = stream({})

    helper.net(plain, stream({}))
    helper.assert_refused(
        unavailable('соединение оборвалось: сервер молчит', 'ldap://ldap.example.org'),
        link.open(endpoint(true), 105)
    )
    t.assert_equals(plain.closed, 1)
end

g.test_starttls_answered_by_another_operation_is_malformed = function()
    helper.net(stream({ helper.bound(1) }), stream({}))
    helper.assert_refused({
        kind = 'malformed',
        message = 'каталог ldap://ldap.example.org ответил не по протоколу: '
            .. 'ждали ответа на сообщение 1, а пришло 1 с тегом 0x61',
    }, link.open(endpoint(true), 105))
end

g.test_starttls_that_could_not_be_sent_is_unavailable = function()
    local plain = stream({})

    plain.write = function()
        return nil, 'Broken pipe'
    end

    helper.net(plain, stream({}))
    helper.assert_refused(
        unavailable('соединение оборвалось: Broken pipe', 'ldap://ldap.example.org'),
        link.open(endpoint(true), 105)
    )
end

g.test_a_refused_connection_names_the_reason = function()
    helper.net(stream({}), stream({}), {
        connect = function()
            return nil, 'Connection refused'
        end,
    })
    helper.assert_refused(
        unavailable('соединение не открылось: Connection refused'),
        link.open(endpoint(false), 105)
    )

    helper.net(stream({}), stream({}), {
        connect = function()
            error('нет сети', 0)
        end,
    })
    helper.assert_refused(
        unavailable('соединение не открылось: нет сети'),
        link.open(endpoint(false), 105)
    )
end

g.test_a_failed_handshake_closes_the_socket = function()
    local net = helper.net(stream({}), nil)

    helper.assert_refused(
        unavailable('рукопожатие TLS не прошло: сертификат не принят'),
        link.open(endpoint(false), 105)
    )
    t.assert_equals(net.plain.closed, 1)
end

g.test_nothing_opens_after_the_deadline = function()
    local net = helper.net(stream({}), stream({}))

    helper.assert_refused(
        unavailable('не ответил за срок вызова'),
        link.open(endpoint(false), 100)
    )
    t.assert_equals(net.connected, {})
end

g.test_starttls_that_took_the_whole_deadline_leaves_no_handshake = function()
    local plain = stream({ helper.extended(1) })
    local net = helper.net(plain, stream({}), { scheduler_now = ticking(100, 1) })

    -- Вопросы к часам: соединение, отправка, два чтения, остаток перед TLS.
    helper.assert_refused(
        unavailable('не ответил за срок вызова', 'ldap://ldap.example.org'),
        link.open(endpoint(true), 104)
    )
    t.assert_equals(net.wrapped, {})
    t.assert_equals(plain.closed, 1)
end

g.test_the_handshake_gets_what_is_left = function()
    local net = helper.net(stream({ helper.extended(1) }), stream({}), { scheduler_now = ticking(100, 1) })

    t.assert_not_equals(link.open(endpoint(true), 105), nil)
    t.assert_equals(net.connected[1].timeout, 5)
    t.assert_equals(net.wrapped[1].options.timeout, 1)
end

g.test_a_message_is_read_piece_by_piece = function()
    local raw = helper.anna(2)
    local chunks = {}

    for at = 1, #raw do
        table.insert(chunks, raw:sub(at, at))
    end

    local io = stream(chunks)

    helper.net(stream({}), stream({}))

    local answer = link.receive(over(io), 105)

    t.assert_equals(answer.dn, helper.DN)
    t.assert_equals(#answer.attributes, 3)
    t.assert_equals(io.timeouts[1], 5)
    t.assert_equals(#io.timeouts, #raw)
end

g.test_a_message_is_read_no_further_than_its_end = function()
    local first = helper.bound(1)
    local second = helper.anna(2)
    local io = stream({ first:sub(1, 5), first:sub(6) .. second })

    helper.net(stream({}), stream({}))

    local connection = over(io)

    t.assert_equals(link.receive(connection, 105), { id = 1, tag = 0x61, code = 0, diagnostic = '' })
    t.assert_equals(link.receive(connection, 105).dn, helper.DN)
end

g.test_a_long_message_is_read_whole = function()
    local long = helper.entry(2, 'cn=x', { { 'description', { string.rep('д', 200) } } })

    t.assert_equals(long:byte(2), 0x82)

    helper.net(stream({}), stream({}))

    local answer = link.receive(over(stream({ long })), 105)

    t.assert_equals(answer.attributes[1].values[1], string.rep('д', 200))
end

g.test_the_limit_itself_is_readable = function()
    t.assert_equals(link.MAX_MESSAGE, 1024 * 1024)
    t.assert_equals(helper.ldap.MAX_MESSAGE, 1024 * 1024)

    local body = helper.int(2) .. helper.tlv(0x73, helper.octets(string.rep('x', 1024 * 1024 - 13)))
    local raw = '\48\131\16\0\0' .. body

    t.assert_equals(#body, 1024 * 1024)
    helper.net(stream({}), stream({}))

    local answer = link.receive(over(stream({ raw })), 105)

    t.assert_equals(answer, { id = 2, tag = 0x73 })

    local over_limit = '\48\131\16\0\1'

    helper.assert_refused({
        kind = 'malformed',
        message = ('каталог %s ответил не по протоколу: сообщение в 1048577 байтов — больше предела 1048576'):format(
            helper.WHERE
        ),
    }, link.receive(over(stream({ over_limit })), 105))
end

g.test_an_indefinite_length_is_malformed = function()
    helper.net(stream({}), stream({}))
    helper.assert_refused({
        kind = 'malformed',
        message = ('каталог %s ответил не по протоколу: '):format(helper.WHERE)
            .. 'длина BER неопределённая, а LDAP знает только определённую',
    }, link.receive(over(stream({ '\48\128' })), 105))
end

g.test_a_message_must_be_a_sequence = function()
    helper.net(stream({}), stream({}))

    for _, raw in ipairs({ '\31\1x', '\49\0', '\4\1x' }) do
        local io = stream({ raw })

        helper.assert_refused({
            kind = 'malformed',
            message = ('каталог %s ответил не по протоколу: '):format(helper.WHERE)
                .. ('сообщение начинается тегом 0x%02X, а не последовательностью'):format(
                    raw:byte(1)
                ),
        }, link.receive(over(io), 105))
        t.assert_equals(io.timeouts, { 5 })
    end
end

g.test_a_broken_message_is_malformed = function()
    helper.net(stream({}), stream({}))
    helper.assert_refused({
        kind = 'malformed',
        message = ('каталог %s ответил не по протоколу: сообщение каталога не по RFC 4511'):format(
            helper.WHERE
        ),
    }, link.receive(over(stream({ helper.tlv(0x30, helper.octets('x')) })), 105))
end

g.test_a_notice_of_disconnection_is_unavailable = function()
    helper.net(stream({}), stream({}))
    helper.assert_refused(
        unavailable('закрывает соединение: server shutting down'),
        link.receive(over(stream({ helper.extended(0, 52, 'server shutting down') })), 105)
    )
end

g.test_every_part_of_a_message_may_break = function()
    local raw = helper.bound(1)

    helper.net(stream({}), stream({}))

    for _, cut in ipairs({ 0, 1, 2, #raw - 1 }) do
        local chunks = cut > 0 and { raw:sub(1, cut) } or {}

        table.insert(chunks, function()
            return ''
        end)
        helper.assert_refused(
            unavailable('закрыл соединение посреди ответа'),
            link.receive(over(stream(chunks)), 105)
        )
    end

    local long = helper.entry(2, 'cn=x', { { 'description', { string.rep('д', 200) } } })

    helper.assert_refused(
        unavailable('соединение оборвалось: сервер молчит'),
        link.receive(over(stream({ long:sub(1, 3) })), 105)
    )
end

g.test_a_read_that_throws_is_a_broken_connection = function()
    helper.net(stream({}), stream({}))
    helper.assert_refused(
        unavailable('соединение оборвалось: attempt to use closed socket'),
        link.receive(
            over(stream({
                function()
                    error('attempt to use closed socket', 0)
                end,
            })),
            105
        )
    )
    helper.assert_refused(
        unavailable('соединение оборвалось: сокет не назвал причины'),
        link.receive(
            over(stream({
                function()
                    return nil
                end,
            })),
            105
        )
    )
end

g.test_a_read_past_the_deadline_is_a_timeout = function()
    helper.net(stream({}), stream({}), { scheduler_now = ticking(100, 5) })

    local io = stream({ '\48', helper.bound(1):sub(2) })

    helper.assert_refused(unavailable('не ответил за срок вызова'), link.receive(over(io), 105))
    t.assert_equals(io.timeouts, { 5 })
end

g.test_a_read_that_fails_at_the_deadline_is_a_timeout = function()
    helper.net(stream({}), stream({}), { scheduler_now = ticking(100, 5) })
    helper.assert_refused(
        unavailable('не ответил за срок вызова'),
        link.receive(
            over(stream({
                function()
                    return nil
                end,
            })),
            105
        )
    )
end

g.test_a_request_takes_the_next_number = function()
    local io = stream({})
    local connection = over(io)

    helper.net(stream({}), stream({}))

    t.assert_equals(link.request(connection, helper.message.unbind, 105), 1)
    t.assert_equals(link.request(connection, helper.message.unbind, 105), 2)
    t.assert_equals(connection.next_id, 3)
    t.assert_equals(io.written, { helper.unbind_request(1), helper.unbind_request(2) })
    t.assert_equals(io.timeouts, { 5, 5 })
end

g.test_a_write_that_fails_is_a_broken_connection = function()
    local io = stream({})

    helper.net(stream({}), stream({}))

    io.write = function()
        return false, 'соединение закрыто'
    end
    helper.assert_refused(
        unavailable('соединение оборвалось: соединение закрыто'),
        link.request(over(io), helper.message.unbind, 105)
    )

    io.write = function()
        error('attempt to use closed socket', 0)
    end
    helper.assert_refused(
        unavailable('соединение оборвалось: attempt to use closed socket'),
        link.send(over(io), 'x', 105)
    )
end

g.test_nothing_is_written_after_the_deadline = function()
    local io = stream({})

    helper.net(stream({}), stream({}))
    helper.assert_refused(unavailable('не ответил за срок вызова'), link.send(over(io), 'x', 100))
    t.assert_equals(io.written, {})
end

g.test_a_write_that_fails_at_the_deadline_is_a_timeout = function()
    local io = stream({})

    io.write = function()
        return nil
    end

    helper.net(stream({}), stream({}), { scheduler_now = ticking(100, 5) })
    helper.assert_refused(unavailable('не ответил за срок вызова'), link.send(over(io), 'x', 105))
end

g.test_an_answer_must_match_the_request = function()
    helper.net(stream({}), stream({}))

    local bound = { [0x61] = true }

    t.assert_equals(link.answer(over(stream({ helper.bound(3) })), 3, bound, 105), {
        id = 3,
        tag = 0x61,
        code = 0,
        diagnostic = '',
    })
    helper.assert_refused({
        kind = 'malformed',
        message = ('каталог %s ответил не по протоколу: ждали ответа на сообщение 3, а пришло 4 с тегом 0x61'):format(
            helper.WHERE
        ),
    }, link.answer(over(stream({ helper.bound(4) })), 3, bound, 105))
    helper.assert_refused({
        kind = 'malformed',
        message = ('каталог %s ответил не по протоколу: ждали ответа на сообщение 3, а пришло 3 с тегом 0x65'):format(
            helper.WHERE
        ),
    }, link.answer(over(stream({ helper.done(3) })), 3, bound, 105))
    helper.assert_refused(
        unavailable('соединение оборвалось: сервер молчит'),
        link.answer(over(stream({})), 3, bound, 105)
    )
end

g.test_close_says_goodbye_and_closes = function()
    local io = stream({})
    local connection = over(io)

    connection.next_id = 5
    link.close(connection)

    t.assert_equals(io.written, { helper.unbind_request(5) })
    t.assert_equals(io.timeouts, { 1 })
    t.assert_equals(io.closed, 1)
end

g.test_close_survives_a_dead_connection = function()
    local io = stream({})

    io.write = function()
        error('attempt to use closed socket')
    end
    io.close = function()
        error('attempt to use closed socket')
    end

    link.close(over(io))
end
