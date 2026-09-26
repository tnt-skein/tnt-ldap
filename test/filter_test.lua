--- Проверки фильтра: экранирование, разбор строки RFC 4515, запись BER.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.filter')

local filter = helper.filter
local tlv = helper.tlv
local octets = helper.octets

--- Сравнение с тегом: имя и значение октетными строками.
local function compare(tag, name, value)
    return tlv(tag, octets(name) .. octets(value))
end

g.test_escape_codes_every_markup_byte = function()
    t.assert_equals(filter.escape('*)(uid=*'), '\\2a\\29\\28uid=\\2a')
    t.assert_equals(filter.escape('a\\b\0c'), 'a\\5cb\\00c')
    t.assert_equals(filter.escape('Анна =:~<>'), 'Анна =:~<>')
    t.assert_equals(filter.escape(''), '')
    t.assert_equals(helper.ldap.escape('*'), '\\2a')
end

g.test_escaped_value_reads_back_as_value = function()
    local name = '*)(uid=*\\\0'

    t.assert_equals(filter.encode('(uid=' .. filter.escape(name) .. ')'), compare(0xA3, 'uid', name))
end

g.test_comparisons = function()
    t.assert_equals(filter.encode('(uid=anna)'), compare(0xA3, 'uid', 'anna'))
    t.assert_equals(filter.encode('(age>=18)'), compare(0xA5, 'age', '18'))
    t.assert_equals(filter.encode('(age<=65)'), compare(0xA6, 'age', '65'))
    t.assert_equals(filter.encode('(cn~=anna)'), compare(0xA8, 'cn', 'anna'))
    t.assert_equals(filter.encode('(member=cn=x,dc=y)'), compare(0xA3, 'member', 'cn=x,dc=y'))
    t.assert_equals(filter.encode('(uid=)'), compare(0xA3, 'uid', ''))
    t.assert_equals(filter.encode('(cn;lang-ru=Анна)'), compare(0xA3, 'cn;lang-ru', 'Анна'))
    t.assert_equals(filter.encode('(2.5.4.3=x)'), compare(0xA3, '2.5.4.3', 'x'))
    t.assert_equals(filter.encode('(c=RU)'), compare(0xA3, 'c', 'RU'))
    t.assert_equals(filter.encode('(cn=\\2A\\5c)'), compare(0xA3, 'cn', '*\\'))
end

g.test_presence_and_substrings = function()
    t.assert_equals(filter.encode('(cn=*)'), tlv(0x87, 'cn'))
    t.assert_equals(
        filter.encode('(cn=an*na)'),
        tlv(0xA4, octets('cn') .. tlv(0x30, tlv(0x80, 'an') .. tlv(0x82, 'na')))
    )
    t.assert_equals(filter.encode('(cn=an*)'), tlv(0xA4, octets('cn') .. tlv(0x30, tlv(0x80, 'an'))))
    t.assert_equals(filter.encode('(cn=*na)'), tlv(0xA4, octets('cn') .. tlv(0x30, tlv(0x82, 'na'))))
    t.assert_equals(filter.encode('(cn=*n*)'), tlv(0xA4, octets('cn') .. tlv(0x30, tlv(0x81, 'n'))))
    t.assert_equals(
        filter.encode('(cn=a*b*c*d)'),
        tlv(0xA4, octets('cn') .. tlv(0x30, tlv(0x80, 'a') .. tlv(0x81, 'b') .. tlv(0x81, 'c') .. tlv(0x82, 'd')))
    )
    t.assert_equals(filter.encode('(cn=\\2a*)'), tlv(0xA4, octets('cn') .. tlv(0x30, tlv(0x80, '*'))))
end

g.test_lists_and_negation = function()
    local uid = compare(0xA3, 'uid', 'anna')
    local person = compare(0xA3, 'objectClass', 'person')

    t.assert_equals(filter.encode('(&(objectClass=person)(uid=anna))'), tlv(0xA0, person .. uid))
    t.assert_equals(filter.encode('(|(uid=anna))'), tlv(0xA1, uid))
    t.assert_equals(filter.encode('(!(uid=anna))'), tlv(0xA2, uid))
    t.assert_equals(
        filter.encode('(&(|(uid=anna)(cn=*))(!(objectClass=person)))'),
        tlv(0xA0, tlv(0xA1, uid .. tlv(0x87, 'cn')) .. tlv(0xA2, person))
    )
end

g.test_extensible_match = function()
    t.assert_equals(
        filter.encode('(userAccountControl:1.2.840.113556.1.4.803:=2)'),
        tlv(0xA9, tlv(0x81, '1.2.840.113556.1.4.803') .. tlv(0x82, 'userAccountControl') .. tlv(0x83, '2'))
    )
    t.assert_equals(
        filter.encode('(cn:dn:2.5.13.5:=Анна)'),
        tlv(0xA9, tlv(0x81, '2.5.13.5') .. tlv(0x82, 'cn') .. tlv(0x83, 'Анна') .. tlv(0x84, '\255'))
    )
    t.assert_equals(filter.encode('(cn:DN:=x)'), tlv(0xA9, tlv(0x82, 'cn') .. tlv(0x83, 'x') .. tlv(0x84, '\255')))
    t.assert_equals(filter.encode('(cn:=x)'), tlv(0xA9, tlv(0x82, 'cn') .. tlv(0x83, 'x')))
    t.assert_equals(filter.encode('(:caseExactMatch:=x)'), tlv(0xA9, tlv(0x81, 'caseExactMatch') .. tlv(0x83, 'x')))
    t.assert_equals(
        filter.encode('(:dn:2.5.13.5:=\\2a)'),
        tlv(0xA9, tlv(0x81, '2.5.13.5') .. tlv(0x83, '*') .. tlv(0x84, '\255'))
    )
end

--- Отказ разбора с текстом после имени фильтра.
local function refused(text, why)
    t.assert_equals({ filter.encode(text) }, { nil, ('фильтр «%s»: %s'):format(text, why) })
end

g.test_broken_structure_is_refused = function()
    refused('uid=anna', 'на месте 1 ждали «(»')
    refused('(uid=anna', 'нет закрывающей скобки')
    refused('(uid=anna))', 'после фильтра лишнее с места 11')
    refused('(uid=anna) ', 'после фильтра лишнее с места 11')
    refused('(&)', 'в «&» пустой список условий')
    refused('(|)', 'в «|» пустой список условий')
    refused('(&(uid=a)', 'на месте 10 ждали «)»')
    refused('(&(uid=a)x)', 'на месте 10 ждали «)»')
    refused('(!(uid=a)', 'на месте 10 ждали «)»')
    refused('(!(uid=a)(cn=b))', 'на месте 10 ждали «)»')
    refused('(!uid=a)', 'на месте 3 ждали «(»')
    refused('(&(uid=a)(cn=b)', 'на месте 16 ждали «)»')
    refused('(&(uid=a)(cn)', 'в условии «cn» нет сравнения')
    refused('(!(cn))', 'в условии «cn» нет сравнения')
    refused('()', 'в условии «» нет сравнения')
end

g.test_broken_items_are_refused = function()
    refused('(=anna)', '«» — не имя атрибута')
    refused('(u id=anna)', '«u id» — не имя атрибута')
    refused('(-uid=anna)', '«-uid» — не имя атрибута')
    refused(
        '(uid=an(na)',
        'скобка и нулевой байт в значении пишутся кодом: \\28, \\00'
    )
    refused(
        '(uid=an\0na)',
        'скобка и нулевой байт в значении пишутся кодом: \\28, \\00'
    )
    refused(
        '(uid=an\\na)',
        'после \\ в значении — две шестнадцатеричные цифры'
    )
    refused('(uid=an\\2)', 'после \\ в значении — две шестнадцатеричные цифры')
    refused('(uid=\\x)', 'после \\ в значении — две шестнадцатеричные цифры')
    refused('(uid=\\)', 'после \\ в значении — две шестнадцатеричные цифры')
    refused(
        '(uid=a\\5c\\)',
        'после \\ в значении — две шестнадцатеричные цифры'
    )
    refused('(cn=a**b)', 'две звёздочки подряд: пустой части подстроки нет')
    refused(
        '(cn=a*(*b)',
        'скобка и нулевой байт в значении пишутся кодом: \\28, \\00'
    )
    refused('(cn=**)', 'две звёздочки подряд: пустой части подстроки нет')
    refused(
        '(age>=1*)',
        'звёздочка-разметка годится только в равенстве, а звёздочка-значение пишется кодом \\2a'
    )
    refused(
        '(cn:=a*)',
        'звёздочка-разметка годится только в равенстве, а звёздочка-значение пишется кодом \\2a'
    )
    refused(
        '(cn:=a(b)',
        'скобка и нулевой байт в значении пишутся кодом: \\28, \\00'
    )
    refused('(:=x)', 'сравнение по правилу пишется attr:dn:правило:=значение')
    refused(
        '(:dn:=x)',
        'сравнение по правилу пишется attr:dn:правило:=значение'
    )
    refused(
        '(cn::=x)',
        'сравнение по правилу пишется attr:dn:правило:=значение'
    )
    refused(
        '(cn:dn:1.2:x:=x)',
        'сравнение по правилу пишется attr:dn:правило:=значение'
    )
    refused('(cn:1 2:=x)', '«1 2» — не имя атрибута')
    refused('(c n:1.2:=x)', '«c n» — не имя атрибута')
    refused('(cn:>=x)', '«cn:» — не имя атрибута')
end
