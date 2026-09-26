--- Проверки настроек: умолчания, адрес, пара служебной учётной записи,
--- фильтр, счёт попыток; каждый бросок — на строке вызова `new`.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.settings')

---@type any
local ldap = helper.ldap
local options = helper.options

--- Обычные настройки без названных ключей.
---@param ... string
---@return table
local function without(...)
    local chosen = options()

    for _, key in ipairs({ ... }) do
        chosen[key] = nil
    end

    return chosen
end

--- Двойники ограничителя и предела: только то, что у них спрашивают.
local limiter = {
    consume = function()
        return { allowed = true }
    end,
}
local limit = {
    by = function(self)
        return self
    end,
}

g.test_defaults_fill_what_is_not_said = function()
    local directory = ldap.new({ url = 'ldaps://ldap.example.org', base = helper.BASE, limiter = false })

    t.assert_equals(directory.name, 'ldap')
    t.assert_equals(directory.settings, {
        name = 'ldap',
        where = 'ldaps://ldap.example.org',
        host = 'ldap.example.org',
        port = 636,
        starttls = false,
        tls = {},
        timeout = 5,
        base = helper.BASE,
        scope = 'sub',
        filter = '(uid={username})',
        subject = 'entryUUID',
        display = 'cn',
        attributes = { 'memberOf' },
    })
end

g.test_every_setting_reaches_the_client = function()
    local attributes = { 'mail', 'memberOf' }
    local tls = { verify = false, ca_file = '/etc/ssl/own.pem', ca_path = '/etc/ssl/own', sni = 'ldap' }
    local directory = ldap.new(options({
        name = 'corp.ad-1',
        url = 'ldap://dc1.corp.example.org:3268/',
        timeout = 0.5,
        tls = tls,
        scope = 'one',
        filter = '(&(objectClass=user)(sAMAccountName={username}))',
        subject = 'objectGUID',
        display = 'displayName',
        attributes = attributes,
        limiter = limiter,
        limit = limit,
    }))

    t.assert_equals(directory.settings, {
        name = 'corp.ad-1',
        where = 'ldap://dc1.corp.example.org:3268',
        host = 'dc1.corp.example.org',
        port = 3268,
        starttls = true,
        tls = tls,
        timeout = 0.5,
        bind_dn = helper.BIND_DN,
        bind_password = helper.BIND_PASSWORD,
        base = helper.BASE,
        scope = 'one',
        filter = '(&(objectClass=user)(sAMAccountName={username}))',
        subject = 'objectGUID',
        display = 'displayName',
        attributes = attributes,
        limiter = limiter,
        limit = limit,
    })

    -- Настройки копируются: правка чужой таблицы не доходит до клиента.
    t.assert_not_equals(rawequal(directory.settings.attributes, attributes), true)
    t.assert_not_equals(rawequal(directory.settings.tls, tls), true)
end

g.test_addresses_name_host_and_port = function()
    local cases = {
        { 'ldap://ldap.example.org', 'ldap.example.org', 389, true },
        { 'ldaps://ldap.example.org/', 'ldap.example.org', 636, false },
        { 'ldaps://10.0.0.7:1636', '10.0.0.7', 1636, false },
        { 'ldap://[::1]', '::1', 389, true },
        { 'ldaps://[fe80::1]:1', 'fe80::1', 1, false },
        { 'ldaps://h:65535', 'h', 65535, false },
    }

    for _, case in ipairs(cases) do
        local settings = ldap.new(options({ url = case[1] })).settings

        t.assert_equals({ settings.host, settings.port, settings.starttls }, { case[2], case[3], case[4] }, case[1])
    end

    t.assert_equals(ldap.new(options({ url = 'ldap://[::1]:10389' })).settings.where, 'ldap://[::1]:10389')
end

--- Адрес ldap:// без TLS не бывает: ни словом, ни схемой.
local URL =
    'настройки.url — адрес ldaps://узел[:порт] либо ldap://узел[:порт], а не '

g.test_a_broken_address_is_blamed_on_the_caller = function()
    helper.assert_blamed({
        {
            function()
                ldap.new(options({ url = 'http://ldap.example.org' }))
            end,
            URL .. '«http://ldap.example.org»',
        },
        {
            function()
                ldap.new(options({ url = 'LDAP://ldap.example.org' }))
            end,
            URL .. '«LDAP://ldap.example.org»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://ldap.example.org/dc=example' }))
            end,
            URL .. '«ldap://ldap.example.org/dc=example»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://ldap.example.org?uid' }))
            end,
            URL .. '«ldap://ldap.example.org?uid»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://' }))
            end,
            'настройки.url: узел и порт не разобрать в «»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap:///' }))
            end,
            'настройки.url: узел и порт не разобрать в «»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://[]' }))
            end,
            'настройки.url: узел и порт не разобрать в «[]»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://:389' }))
            end,
            'настройки.url: узел и порт не разобрать в «:389»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://host:' }))
            end,
            'настройки.url: узел и порт не разобрать в «host:»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://host:x' }))
            end,
            'настройки.url: узел и порт не разобрать в «host:x»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://reader@host' }))
            end,
            'настройки.url: узел и порт не разобрать в «reader@host»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://[::1]x' }))
            end,
            'настройки.url: узел и порт не разобрать в «[::1]x»',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://host:0' }))
            end,
            'настройки.url: порт — число от 1 до 65535, а не 0',
        },
        {
            function()
                ldap.new(options({ url = 'ldap://host:65536' }))
            end,
            'настройки.url: порт — число от 1 до 65535, а не 65536',
        },
    })
end

g.test_a_name_is_a_provider_name = function()
    t.assert_equals(ldap.new(options({ name = 'a' })).name, 'a')
    t.assert_equals(ldap.new(options({ name = 'a' .. string.rep('b', 63) })).name, 'a' .. string.rep('b', 63))

    local shape =
        'настройки.name — строчная латиница, цифры, «_», «.» и «-», с буквы, а не '

    helper.assert_blamed({
        {
            function()
                ldap.new(options({ name = 'LDAP' }))
            end,
            shape .. '«LDAP»',
        },
        {
            function()
                ldap.new(options({ name = '1ldap' }))
            end,
            shape .. '«1ldap»',
        },
        {
            function()
                ldap.new(options({ name = '' }))
            end,
            shape .. '«»',
        },
        {
            function()
                ldap.new(options({ name = 'a' .. string.rep('b', 64) }))
            end,
            'настройки.name — строка длиной от 1 до 64 знаков, а не 65',
        },
        {
            function()
                ldap.new(options({ name = helper.wrong(7) }))
            end,
            'настройки.name — строка, а не число',
        },
    })
end

g.test_a_service_account_goes_in_pairs = function()
    local directory = ldap.new(without('bind_dn', 'bind_password'))

    t.assert_equals({ directory.settings.bind_dn, directory.settings.bind_password }, { nil, nil })

    local pair =
        'настройки.bind_dn и bind_password — только парой: DN без пароля каталог пускает без проверки'
    local lonely_dn = without('bind_password')
    local lonely_password = without('bind_dn')

    helper.assert_blamed({
        {
            function()
                ldap.new(lonely_dn)
            end,
            pair,
        },
        {
            function()
                ldap.new(lonely_password)
            end,
            pair,
        },
        {
            function()
                ldap.new(options({ bind_password = '' }))
            end,
            'настройки.bind_password — непустая строка, а не пустая',
        },
    })
end

g.test_a_filter_needs_the_username_in_a_value = function()
    helper.assert_blamed({
        {
            function()
                ldap.new(options({ filter = '(uid=anna)' }))
            end,
            'настройки.filter: нет {username} — искать некого',
        },
        {
            function()
                ldap.new(options({ filter = '(uid={username}' }))
            end,
            'настройки.filter: фильтр «(uid={username}»: нет закрывающей скобки',
        },
        {
            function()
                ldap.new(options({ filter = '({username}=anna)' }))
            end,
            'настройки.filter: фильтр «({username}=anna)»: «{username}» — не имя атрибута',
        },
    })
end

g.test_other_settings_are_checked = function()
    helper.assert_blamed({
        {
            function()
                ldap.new(options({ timeout = 0 }))
            end,
            'настройки.timeout — число больше 0, а не 0',
        },
        {
            function()
                ldap.new(options({ scope = 'subtree' }))
            end,
            'настройки.scope — одно из «base», «one», «sub», а не «subtree»',
        },
        {
            function()
                ldap.new(without('base'))
            end,
            'настройки.base — строка, а не nil',
        },
        {
            function()
                ldap.new(options({ tls = { verify = 'false' } }))
            end,
            'настройки.tls.verify — логическое значение, а не строка',
        },
        {
            function()
                ldap.new(options({ bind = 'x' }))
            end,
            'настройки: ключа «bind» нет, есть attributes, base, bind_dn, bind_password, display, filter, '
                .. 'limit, limiter, name, scope, subject, timeout, tls, url',
        },
        {
            function()
                ldap.new(helper.wrong('ldaps://ldap.example.org'))
            end,
            'настройки — таблица, а не строка',
        },
    })
end

g.test_attempts_are_counted_or_refused_in_words = function()
    local counted = ldap.new(options({ limiter = limiter, limit = limit }))

    t.assert_equals({ counted.settings.limiter, counted.settings.limit }, { limiter, limit })
    t.assert_equals(ldap.new(options({ limiter = false })).settings.limiter, nil)

    local needed =
        'настройки.limiter: счёт попыток обязателен — ограничитель tnt-throttle либо false'
    local limited =
        'настройки.limit: нужен предел tnt-throttle — throttle.per_minute(5) и подобные'

    helper.assert_blamed({
        {
            function()
                ldap.new(without('limiter'))
            end,
            needed,
        },
        {
            function()
                ldap.new(options({ limiter = helper.wrong(true) }))
            end,
            needed,
        },
        {
            function()
                ldap.new(options({ limiter = {}, limit = limit }))
            end,
            needed,
        },
        {
            function()
                ldap.new(options({ limiter = limiter }))
            end,
            limited,
        },
        {
            function()
                ldap.new(options({ limiter = limiter, limit = helper.wrong(5) }))
            end,
            limited,
        },
        {
            function()
                ldap.new(options({ limiter = limiter, limit = {} }))
            end,
            limited,
        },
        {
            function()
                ldap.new(options({ limiter = false, limit = limit }))
            end,
            'настройки.limit: предел без ограничителя не считается — нужен limiter',
        },
    })
end
