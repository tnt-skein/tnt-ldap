--- Проверки поиска записей: запрос, записи с атрибутами, отказы, аргументы.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.search')

local tlv = helper.tlv
local octets = helper.octets

--- Группы Анны.
local QUERY = {
    base = 'ou=groups,dc=example,dc=org',
    filter = '(member=' .. helper.ldap.escape(helper.DN) .. ')',
    attributes = { 'cn' },
}

--- Запись группы.
local function group(id, name, attributes)
    return helper.entry(id, ('cn=%s,ou=groups,dc=example,dc=org'):format(name), attributes or { { 'cn', { name } } })
end

g.after_each(helper.restore)

g.test_entries_come_with_their_attributes = function()
    local directory, net = helper.connected({
        helper.bound(1),
        group(2, 'operators', { { 'CN', { 'operators' } }, { 'objectClass', { 'groupOfNames', 'top' } } }),
        helper.reference(2),
        group(2, 'admins'),
        helper.done(2),
    })

    t.assert_equals(directory:search(QUERY), {
        {
            dn = 'cn=operators,ou=groups,dc=example,dc=org',
            attributes = { cn = { 'operators' }, objectClass = { 'groupOfNames', 'top' } },
        },
        { dn = 'cn=admins,ou=groups,dc=example,dc=org', attributes = { cn = { 'admins' } } },
    })

    local body = octets('ou=groups,dc=example,dc=org')
        .. helper.int(2, 0x0A)
        .. helper.int(0, 0x0A)
        .. helper.int(1000)
        .. helper.int(5)
        .. tlv(0x01, '\0')
        .. tlv(0xA3, octets('member') .. octets(helper.DN))
        .. tlv(0x30, octets('cn'))

    t.assert_equals(net.secured.written, {
        helper.bind_request(1, helper.BIND_DN, helper.BIND_PASSWORD),
        helper.envelope(2, tlv(0x63, body)),
        helper.unbind_request(3),
    })
    t.assert_equals(net.secured.closed, 1)
end

g.test_scope_limit_and_attributes_are_the_callers = function()
    local directory, net = helper.connected({ helper.bound(1), helper.done(2) })

    t.assert_equals(
        directory:search({ base = helper.BASE, scope = 'one', filter = '(objectClass=*)', size_limit = 300 }),
        {}
    )

    local body = octets(helper.BASE)
        .. helper.int(1, 0x0A)
        .. helper.int(0, 0x0A)
        .. helper.int(300)
        .. helper.int(5)
        .. tlv(0x01, '\0')
        .. tlv(0x87, 'objectClass')
        .. tlv(0x30, '')

    t.assert_equals(net.secured.written[2], helper.envelope(2, tlv(0x63, body)))
    t.assert_equals(helper.directory.SIZE_LIMIT, 1000)
end

g.test_more_entries_than_asked_are_malformed = function()
    local directory = helper.connected({ helper.bound(1), group(2, 'a'), group(2, 'b') })

    helper.assert_refused({
        kind = 'malformed',
        message = 'каталог ldaps://ldap.example.org прислал больше 1 записей, чем просили',
    }, directory:search({ base = '', filter = '(cn=*)', size_limit = 1 }))
end

g.test_a_failed_search_is_the_directory_refusal = function()
    local directory = helper.connected({ helper.bound(1), group(2, 'a'), helper.done(2, 4, 'size limit exceeded') })

    helper.assert_refused({
        kind = 'rejected',
        message = 'каталог ldaps://ldap.example.org не выполнил поиск: код 4: size limit exceeded',
        code = 4,
        diagnostic = 'size limit exceeded',
    }, directory:search(QUERY))
end

g.test_a_lost_connection_and_a_refused_account_are_refusals = function()
    local directory = helper.connected({ helper.bound(1), group(2, 'a') })

    helper.assert_refused({
        kind = 'unavailable',
        message = 'каталог ldaps://ldap.example.org: соединение оборвалось: сервер молчит',
    }, directory:search(QUERY))

    directory = helper.connected({ helper.bound(1, 50, 'no access') })
    helper.assert_refused({
        kind = 'rejected',
        message = 'каталог ldaps://ldap.example.org не пустил служебную учётную запись: код 50: no access',
        code = 50,
        diagnostic = 'no access',
    }, directory:search(QUERY))
end

g.test_arguments_are_checked = function()
    local directory = helper.connected({})

    helper.assert_blamed({
        {
            function()
                directory:search({ base = '', filter = '(cn=a' })
            end,
            'поиск.filter: фильтр «(cn=a»: нет закрывающей скобки',
        },
        {
            function()
                directory:search({ base = '', filter = '(cn=a)', size_limit = 0 })
            end,
            'поиск.size_limit — число больше 0, а не 0',
        },
        {
            function()
                directory:search({ base = '', filter = '(cn=a)', size_limit = 1.5 })
            end,
            'поиск.size_limit — целое число, а не 1.5',
        },
        {
            function()
                directory:search({ filter = '(cn=a)' })
            end,
            'поиск.base — строка, а не nil',
        },
        {
            function()
                directory:search({ base = '', filter = '(cn=a)', scope = 'subtree' })
            end,
            'поиск.scope — одно из «base», «one», «sub», а не «subtree»',
        },
        {
            function()
                directory:search(helper.wrong(nil))
            end,
            'поиск — таблица, а не nil',
        },
    })
end
