--- Живые проверки против настоящего каталога OpenLDAP (`make ldap-up`).
---
--- Двойник показывает, что мы правильно разговариваем сами с собой;
--- здесь — что нас понимает slapd: TLS с первого байта и StartTLS,
--- `entryUUID` опознавателем, `memberOf`, отказ на неверный пароль
--- и на неизвестное имя, экранирование имени, неоднозначное имя,
--- непринятый сертификат. Без стенда проверки пропускаются.

local fio = require('fio')
local socket = require('socket')
local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.live')

--- Окружение стенда — через `tnt-env`: мимо него окружение не читают
--- и проверки.
local env = helper.stand_env()

--- Где стоит каталог: те же адреса и переменные, что у скрипта стенда.
local HOST = '127.0.0.1'
local PORT = env.int('STAND_LDAP_PORT', 18389)
local TLS_PORT = env.int('STAND_LDAP_TLS_PORT', 18636)
local CA = fio.pathjoin(env.string('LDAP_TLS_DIR', 'test/stand/run/ldap-tls'), 'ca.pem')

local READER = 'cn=readonly,dc=example,dc=org'
local ANNA = 'uid=anna,ou=people,dc=example,dc=org'
local OPERATORS = 'cn=operators,ou=groups,dc=example,dc=org'

--- Слушает ли стенд: без него проверки пропускаются.
local function listening()
    local connection = socket.tcp_connect(HOST, TLS_PORT, 0.3)

    if connection == nil then
        return false
    end

    connection:close()

    return fio.path.exists(CA)
end

g.before_all(function()
    t.skip_if(not listening(), 'каталога нет: make ldap-up')
end)

g.after_each(helper.restore)

--- Клиент стенда: служебная учётная запись только для чтения.
---@param overrides table|nil
---@return table
local function directory(overrides)
    local options = {
        url = ('ldaps://%s:%d'):format(HOST, TLS_PORT),
        tls = { ca_file = CA },
        bind_dn = READER,
        bind_password = 'reader-secret',
        base = 'ou=people,dc=example,dc=org',
        attributes = { 'memberOf', 'mail' },
        limiter = false,
    }

    for key, value in pairs(overrides or {}) do
        options[key] = value
    end

    return helper.ldap.new(options)
end

g.test_ldaps_login_gives_the_entry_uuid = function()
    local assertion, err = directory():authenticate('anna', 'anna-secret')

    t.assert_equals(err, nil)
    t.assert_str_matches(assertion.subject, '%x+%-%x+%-%x+%-%x+%-%x+')
    t.assert_equals(#assertion.subject, 36)
    t.assert_equals(assertion.provider, 'ldap')
    t.assert_equals(assertion.name, 'Анна Петрова')
    t.assert_equals(assertion.methods, { 'pwd' })
    t.assert_equals(assertion.claims, { dn = ANNA, memberOf = { OPERATORS }, mail = { 'anna@example.org' } })
    t.assert_almost_equals(assertion.authenticated_at, require('clock').realtime(), 5)
end

g.test_starttls_login_is_the_same_entry = function()
    local over_tls = directory():authenticate('anna', 'anna-secret')
    local asked = directory({ url = ('ldap://%s:%d'):format(HOST, PORT) }):authenticate('anna', 'anna-secret')

    t.assert_equals(asked.subject, over_tls.subject)
end

g.test_a_wrong_password_and_an_unknown_name_read_the_same = function()
    local _, wrong = directory():authenticate('anna', 'wrong')
    local _, unknown = directory():authenticate('nobody', 'wrong')

    t.assert_equals(
        { wrong.kind, wrong.message, wrong.code },
        { 'invalid', 'неверное имя или пароль', 49 }
    )
    t.assert_equals({ unknown.kind, unknown.message }, { 'invalid', 'неверное имя или пароль' })
end

g.test_markup_in_a_name_finds_nobody = function()
    for _, name in ipairs({ '*', '*)(uid=*', 'ann*' }) do
        local outcome, err = directory():authenticate(name, 'anna-secret')

        t.assert_equals(outcome, nil, name)
        t.assert_equals(err.kind, 'invalid', name)
    end
end

g.test_an_ambiguous_name_is_refused = function()
    local _, err = directory({ filter = '(cn={username})' }):authenticate('Двойник', 'twin-secret')

    t.assert_equals(err.kind, 'malformed')
end

g.test_a_wrong_service_password_is_the_directory_refusal = function()
    local _, err = directory({ bind_password = 'wrong' }):authenticate('anna', 'anna-secret')

    t.assert_equals({ err.kind, err.code }, { 'rejected', 49 })
end

g.test_a_certificate_from_an_unknown_root_is_refused = function()
    local _, err = directory({ tls = {} }):authenticate('anna', 'anna-secret')

    t.assert_equals(err.kind, 'unavailable')
    t.assert_str_contains(err.message, 'рукопожатие TLS не прошло')
end

g.test_groups_are_found_by_search = function()
    local entries, err = directory():search({
        base = 'ou=groups,dc=example,dc=org',
        filter = '(uniqueMember=' .. helper.ldap.escape(ANNA) .. ')',
        attributes = { 'cn' },
    })

    t.assert_equals(err, nil)
    t.assert_equals(entries, { { dn = OPERATORS, attributes = { cn = { 'operators' } } } })
end
