--- Проверки сообщений: запросы клиента байт в байт и разбор ответов.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.message')

local message = helper.message
local tlv = helper.tlv
local octets = helper.octets

g.test_requests_are_written_as_rfc_4511_says = function()
    t.assert_equals(message.bind(1, helper.DN, 'secret'), helper.bind_request(1, helper.DN, 'secret'))
    t.assert_equals(message.bind(300, '', ''), helper.bind_request(300, '', ''))
    t.assert_equals(message.unbind(4), helper.unbind_request(4))
    t.assert_equals(message.unbind(4), '\48\5\2\1\4\66\0')
    t.assert_equals(message.starttls(1), helper.envelope(1, tlv(0x77, tlv(0x80, '1.3.6.1.4.1.1466.20037'))))
end

g.test_a_search_request_carries_every_field = function()
    local encoded = helper.filter.encode('(uid=anna)')

    --- Поиск, каким его пишет клиент: псевдонимы не раскрываются,
    --- «только имена атрибутов» — ложь.
    local function expected(scope, attributes)
        local body = octets(helper.BASE)
            .. helper.int(scope, 0x0A)
            .. helper.int(0, 0x0A)
            .. helper.int(2)
            .. helper.int(5)
            .. tlv(0x01, '\0')
            .. encoded
            .. tlv(0x30, attributes)

        return helper.envelope(7, tlv(0x63, body))
    end

    local request = {
        base = helper.BASE,
        scope = 'one',
        filter = encoded,
        attributes = { 'entryUUID', 'cn' },
        size_limit = 2,
        time_limit = 5,
    }

    t.assert_equals(message.search(7, request), expected(1, octets('entryUUID') .. octets('cn')))

    request.scope = 'base'
    request.attributes = {}
    t.assert_equals(message.search(7, request), expected(0, ''))

    request.scope = 'sub'
    t.assert_equals(message.search(7, request), expected(2, ''))
    t.assert_equals(message.SCOPES, { base = 0, one = 1, sub = 2 })
end

g.test_results_are_read = function()
    t.assert_equals(message.decode(helper.bound(1)), { id = 1, tag = 0x61, code = 0, diagnostic = '' })
    t.assert_equals(
        message.decode(helper.bound(3, 49, 'invalid credentials')),
        { id = 3, tag = 0x61, code = 49, diagnostic = 'invalid credentials' }
    )
    t.assert_equals(message.decode(helper.done(300, 4)), { id = 300, tag = 0x65, code = 4, diagnostic = '' })
    t.assert_equals(
        message.decode(helper.extended(0, 52, 'bye')),
        { id = 0, tag = 0x78, code = 52, diagnostic = 'bye' }
    )

    -- Сверх итога у ответа бывают ссылки и имя операции: они не мешают.
    local extra = helper.envelope(2, tlv(0x78, helper.int(0, 0x0A) .. octets('') .. octets('') .. tlv(0x8A, '1.2')))

    t.assert_equals(message.decode(extra), { id = 2, tag = 0x78, code = 0, diagnostic = '' })
end

g.test_an_entry_is_read_with_its_attributes = function()
    t.assert_equals(message.decode(helper.anna(2)), {
        id = 2,
        tag = 0x64,
        dn = helper.DN,
        attributes = {
            { type = 'entryUUID', values = { helper.UUID } },
            { type = 'cn', values = { 'Анна Петрова' } },
            { type = 'memberOf', values = { helper.GROUP } },
        },
    })
    t.assert_equals(message.decode(helper.entry(2, 'cn=x', {})), { id = 2, tag = 0x64, dn = 'cn=x', attributes = {} })
    t.assert_equals(
        message.decode(helper.entry(2, 'cn=x', { { 'mail', {} }, { 'cn', { 'a', 'b' } } })).attributes,
        { { type = 'mail', values = {} }, { type = 'cn', values = { 'a', 'b' } } }
    )
    t.assert_equals(message.decode(helper.reference(2)), { id = 2, tag = 0x73 })
end

--- Отказ разбора.
local function malformed(raw)
    t.assert_equals({ message.decode(raw) }, { nil, 'сообщение каталога не по RFC 4511' })
end

g.test_a_message_of_wrong_shape_is_refused = function()
    local result = helper.int(0, 0x0A) .. octets('') .. octets('')

    t.assert_equals(
        { message.decode('\48\5\2\1') },
        { nil, 'запись BER длиннее того, что её содержит' }
    )
    malformed(tlv(0x31, helper.int(1) .. tlv(0x61, result)))
    malformed(tlv(0x30, octets('1') .. tlv(0x61, result)))
    malformed(tlv(0x30, helper.int(1)))
    malformed(tlv(0x30, tlv(0x02, '\0\0\0\0\1') .. tlv(0x61, result)))
    malformed(helper.envelope(1, tlv(0x62, result)))
    malformed(helper.envelope(1, octets('x')))
    malformed(helper.envelope(1, tlv(0x61, octets('') .. octets('') .. octets(''))))
    malformed(helper.envelope(1, tlv(0x61, helper.int(0, 0x0A) .. helper.int(0) .. octets(''))))
    malformed(helper.envelope(1, tlv(0x61, helper.int(0, 0x0A) .. octets('') .. helper.int(0))))
    malformed(helper.envelope(1, tlv(0x61, helper.int(0, 0x0A) .. octets(''))))
    malformed(helper.envelope(1, tlv(0x61, tlv(0x0A, '') .. octets('') .. octets(''))))
end

g.test_an_entry_of_wrong_shape_is_refused = function()
    local attribute = tlv(0x30, octets('cn') .. tlv(0x31, octets('a')))

    malformed(helper.envelope(2, tlv(0x64, helper.int(1) .. tlv(0x30, attribute))))
    malformed(helper.envelope(2, tlv(0x64, octets('cn=x') .. tlv(0x31, attribute))))
    malformed(helper.envelope(2, tlv(0x64, octets('cn=x'))))
    malformed(helper.envelope(2, tlv(0x64, octets('cn=x') .. tlv(0x30, octets('cn')))))
    malformed(helper.envelope(2, tlv(0x64, octets('cn=x') .. tlv(0x30, tlv(0x30, helper.int(1) .. tlv(0x31, ''))))))
    malformed(helper.envelope(2, tlv(0x64, octets('cn=x') .. tlv(0x30, tlv(0x30, octets('cn') .. tlv(0x30, ''))))))
    malformed(helper.envelope(2, tlv(0x64, octets('cn=x') .. tlv(0x30, tlv(0x30, octets('cn'))))))
    malformed(
        helper.envelope(2, tlv(0x64, octets('cn=x') .. tlv(0x30, tlv(0x30, octets('cn') .. tlv(0x31, helper.int(1))))))
    )
    malformed(
        helper.envelope(
            2,
            tlv(
                0x64,
                octets('cn=x')
                    .. tlv(0x30, attribute .. tlv(0x30, octets('cn') .. tlv(0x31, octets('a') .. helper.int(1))))
            )
        )
    )
end
