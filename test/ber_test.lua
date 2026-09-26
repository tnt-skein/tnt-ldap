--- Проверки записи BER: длины, целые, заголовок, разбор, глубина.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.ber')

local ber = helper.ber

g.test_a_short_length_is_one_byte = function()
    t.assert_equals(ber.encode(0x04, ''), '\4\0')
    t.assert_equals(ber.encode(0x04, 'ab'), '\4\2ab')
    t.assert_equals(ber.encode(0x04, string.rep('x', 127)), '\4\127' .. string.rep('x', 127))
end

g.test_a_long_length_counts_its_bytes = function()
    t.assert_equals(ber.encode(0x04, string.rep('x', 128)), '\4\129\128' .. string.rep('x', 128))
    t.assert_equals(ber.encode(0x04, string.rep('x', 255)), '\4\129\255' .. string.rep('x', 255))
    t.assert_equals(ber.encode(0x04, string.rep('x', 256)), '\4\130\1\0' .. string.rep('x', 256))
    t.assert_equals(ber.encode(0x30, string.rep('x', 65536)):sub(1, 5), '\48\131\1\0\0')
end

g.test_an_integer_is_minimal_twos_complement = function()
    t.assert_equals(ber.integer(0), '\2\1\0')
    t.assert_equals(ber.integer(5), '\2\1\5')
    t.assert_equals(ber.integer(127), '\2\1\127')
    t.assert_equals(ber.integer(128), '\2\2\0\128')
    t.assert_equals(ber.integer(255), '\2\2\0\255')
    t.assert_equals(ber.integer(256), '\2\2\1\0')
    t.assert_equals(ber.integer(300), '\2\2\1\44')
    t.assert_equals(ber.integer(2 ^ 31 - 1), '\2\4\127\255\255\255')
    t.assert_equals(ber.integer(2, 0x0A), '\10\1\2')
end

g.test_length_bytes_follow_the_first = function()
    t.assert_equals(ber.length_bytes(0), 0)
    t.assert_equals(ber.length_bytes(0x7F), 0)
    t.assert_equals(ber.length_bytes(0x81), 1)
    t.assert_equals(ber.length_bytes(0x84), 4)
    t.assert_equals(
        { ber.length_bytes(0x80) },
        { nil, 'длина BER неопределённая, а LDAP знает только определённую' }
    )
    t.assert_equals(
        { ber.length_bytes(0x85) },
        { nil, 'длина BER в 5 байтах — больше четырёх' }
    )
end

g.test_a_header_gives_tag_start_and_size = function()
    t.assert_equals({ ber.header('\4\2ab', 1) }, { 4, 3, 2 })
    t.assert_equals({ ber.header('xx\4\2ab', 3) }, { 4, 5, 2 })
    t.assert_equals({ ber.header('\48\129\200', 1) }, { 0x30, 4, 200 })
    t.assert_equals({ ber.header('\48\130\1\44', 1) }, { 0x30, 5, 300 })
    t.assert_equals({ ber.header('\48\132\0\1\0\0', 1) }, { 0x30, 7, 65536 })
end

g.test_a_broken_header_is_refused = function()
    t.assert_equals({ ber.header('', 1) }, { nil, 'запись BER оборвана на заголовке' })
    t.assert_equals({ ber.header('\4', 1) }, { nil, 'запись BER оборвана на заголовке' })
    t.assert_equals(
        { ber.header('\31\1x', 1) },
        { nil, 'тег BER многобайтовый, а LDAP таких не знает' }
    )
    t.assert_equals(
        { ber.header('\63\1x', 1) },
        { nil, 'тег BER многобайтовый, а LDAP таких не знает' }
    )
    t.assert_equals({ ber.header('\30\1x', 1) }, { 30, 3, 1 })
    t.assert_equals(
        { ber.header('\4\128', 1) },
        { nil, 'длина BER неопределённая, а LDAP знает только определённую' }
    )
    t.assert_equals({ ber.header('\4\130\1', 1) }, { nil, 'запись BER оборвана на длине' })
    t.assert_equals({ ber.header('\4\130\1\0', 1) }, { 4, 5, 256 })
end

g.test_decode_reads_records_in_order = function()
    local data = '\48\6\2\1\7\4\1a' .. '\4\0'

    t.assert_equals(ber.decode(data), {
        { tag = 0x30, items = { { tag = 2, value = '\7' }, { tag = 4, value = 'a' } } },
        { tag = 4, value = '' },
    })
    t.assert_equals(ber.decode(''), {})
    t.assert_equals(ber.decode('\48\0'), { { tag = 0x30, items = {} } })
end

g.test_decode_refuses_what_does_not_fit = function()
    t.assert_equals(
        { ber.decode('\4\3ab') },
        { nil, 'запись BER длиннее того, что её содержит' }
    )
    t.assert_equals(
        { ber.decode('\48\3\4\3ab') },
        { nil, 'запись BER длиннее того, что её содержит' }
    )
    t.assert_equals(
        { ber.decode('\48\2\4\1a') },
        { nil, 'запись BER длиннее того, что её содержит' }
    )
    t.assert_equals({ ber.decode('\48\1\4') }, { nil, 'запись BER оборвана на заголовке' })
    t.assert_equals({ ber.decode('\4\1a\4') }, { nil, 'запись BER оборвана на заголовке' })
end

--- Вложенность в `depth` составных записей.
---@param depth integer
---@return string
local function nested(depth)
    local data = '\4\1x'

    for _ = 1, depth do
        data = helper.tlv(0x30, data)
    end

    return data
end

g.test_nesting_is_bounded = function()
    t.assert_equals(ber.MAX_DEPTH, 16)

    local deepest = ber.decode(nested(16))
    local node = deepest[1]

    for _ = 2, 16 do
        node = node.items[1]
    end

    t.assert_equals(node.items, { { tag = 4, value = 'x' } })
    t.assert_equals(
        { ber.decode(nested(17)) },
        { nil, 'записи BER вложены глубже 16 уровней' }
    )
end

g.test_an_integer_reads_back = function()
    t.assert_equals(ber.to_integer('\0'), 0)
    t.assert_equals(ber.to_integer('\7'), 7)
    t.assert_equals(ber.to_integer('\1\44'), 300)
    t.assert_equals(ber.to_integer('\127\255\255\255'), 2 ^ 31 - 1)
    t.assert_equals(ber.to_integer('\255'), 255)
    t.assert_equals(ber.to_integer(''), nil)
    t.assert_equals(ber.to_integer('\0\0\0\0\1'), nil)
end
