--- Проверки входа паролем: разговор с каталогом байт в байт, отказы
--- до каталога, неизвестное имя, неверный пароль, удостоверение.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.authenticate')

local tlv = helper.tlv
local octets = helper.octets

--- Отказ «неверное имя или пароль» без слов каталога.
local WRONG = { kind = 'invalid', message = 'неверное имя или пароль' }

--- Тот же отказ, когда каталог ответил на пароль кодом 49.
local REFUSED =
    { kind = 'invalid', message = 'неверное имя или пароль', code = 49, diagnostic = '' }

--- Поиск записи посетителя, каким его пишет клиент.
---@param id integer
---@param encoded string Фильтр записью BER
---@param overrides table|nil База, область, срок, атрибуты
---@return string
local function search_request(id, encoded, overrides)
    local chosen = overrides or {}
    local attributes = {}

    for _, name in ipairs(chosen.attributes or { 'entryUUID', 'cn', 'memberOf' }) do
        table.insert(attributes, octets(name))
    end

    local body = octets(chosen.base or helper.BASE)
        .. helper.int(chosen.scope or 2, 0x0A)
        .. helper.int(0, 0x0A)
        .. helper.int(2)
        .. helper.int(chosen.time or 5)
        .. tlv(0x01, '\0')
        .. encoded
        .. tlv(0x30, table.concat(attributes))

    return helper.envelope(id, tlv(0x63, body))
end

--- Фильтр `(uid=значение)` записью BER.
local function uid(value)
    return tlv(0xA3, octets('uid') .. octets(value))
end

--- Удостоверение Анны.
local function anna()
    return {
        provider = 'ldap',
        subject = helper.UUID,
        name = 'Анна Петрова',
        methods = { 'pwd' },
        authenticated_at = helper.NOW,
        claims = { dn = helper.DN, memberOf = { helper.GROUP } },
    }
end

g.after_each(helper.restore)

g.test_a_right_password_gives_an_assertion = function()
    local directory, net = helper.connected({ helper.bound(1), helper.anna(2), helper.done(2), helper.bound(3) })

    t.assert_equals(directory:authenticate('anna', 'anna-secret'), anna())
    t.assert_equals(net.secured.written, {
        helper.bind_request(1, helper.BIND_DN, helper.BIND_PASSWORD),
        search_request(2, uid('anna')),
        helper.bind_request(3, helper.DN, 'anna-secret'),
        helper.unbind_request(4),
    })
    t.assert_equals(net.secured.closed, 1)
    t.assert_equals(net.connected, { { host = 'ldap.example.org', port = 636, timeout = 5 } })
end

g.test_each_assertion_is_its_own = function()
    local directory = helper.connected({ helper.bound(1), helper.anna(2), helper.done(2), helper.bound(3) })
    local first = directory:authenticate('anna', 'anna-secret')

    first.methods[2] = 'otp'
    helper.connected({ helper.bound(1), helper.anna(2), helper.done(2), helper.bound(3) })
    t.assert_equals(directory:authenticate('anna', 'anna-secret').methods, { 'pwd' })
end

g.test_the_name_goes_into_the_filter_as_a_value = function()
    local name = '*)(uid=*'
    local directory, net = helper.connected({ helper.bound(1), helper.done(2), helper.bound(3, 49) })

    helper.assert_refused(REFUSED, directory:authenticate(name, 'x'))
    t.assert_equals(net.secured.written[2], search_request(2, uid(name)))
end

g.test_the_name_goes_into_every_place_of_the_filter = function()
    local directory, net = helper.connected({ helper.bound(1), helper.done(2), helper.bound(3, 49) }, {
        filter = '(|(uid={username})(mail={username}*))',
    })
    local encoded = tlv(0xA1, uid('a\\b') .. tlv(0xA4, octets('mail') .. tlv(0x30, tlv(0x80, 'a\\b'))))

    directory:authenticate('a\\b', 'x')
    t.assert_equals(net.secured.written[2], search_request(2, encoded))
end

g.test_an_empty_password_never_reaches_the_directory = function()
    local directory, net = helper.connected({})

    helper.assert_refused(WRONG, directory:authenticate('anna', ''))
    helper.assert_refused(WRONG, directory:authenticate('', 'anna-secret'))
    helper.assert_refused(WRONG, directory:authenticate(string.rep('a', 257), 'anna-secret'))
    t.assert_equals(net.connected, {})
end

g.test_the_longest_name_reaches_the_directory = function()
    t.assert_equals(helper.directory.MAX_USERNAME, 256)

    local name = string.rep('a', 256)
    local directory, net = helper.connected({ helper.bound(1), helper.done(2), helper.bound(3, 49) })

    helper.assert_refused(REFUSED, directory:authenticate(name, 'x'))
    t.assert_equals(net.secured.written[2], search_request(2, uid(name)))
end

g.test_arguments_are_checked = function()
    local directory = helper.connected({})

    helper.assert_blamed({
        {
            function()
                directory:authenticate(helper.wrong(nil), 'x')
            end,
            'имя — строка, а не nil',
        },
        {
            function()
                directory:authenticate('anna', helper.wrong(42))
            end,
            'пароль — строка, а не число',
        },
    })
end

g.test_an_unknown_name_still_checks_a_password = function()
    local directory, net = helper.connected({ helper.bound(1), helper.done(2), helper.bound(3, 49, 'no such') })

    helper.assert_refused(
        { kind = 'invalid', message = 'неверное имя или пароль', code = 49, diagnostic = 'no such' },
        directory:authenticate('boris', 'boris-secret')
    )
    t.assert_equals(
        net.secured.written[3],
        helper.bind_request(3, 'cn=tnt-ldap-absent,' .. helper.BASE, 'boris-secret')
    )
    t.assert_equals(net.secured.closed, 1)
end

g.test_an_unknown_name_is_refused_whatever_the_directory_says = function()
    for _, code in ipairs({ 0, 34, 53 }) do
        local directory = helper.connected({ helper.bound(1), helper.done(2), helper.bound(3, code) })
        local outcome, err = directory:authenticate('boris', 'boris-secret')

        t.assert_equals(outcome, nil)
        t.assert_equals(
            { err.kind, err.message, err.code },
            { 'invalid', 'неверное имя или пароль', code }
        )
    end
end

g.test_a_wrong_password_is_invalid = function()
    local directory = helper.connected({
        helper.bound(1),
        helper.anna(2),
        helper.done(2),
        helper.bound(3, 49, '80090308: LdapErr: DSID-0C09044E, data 52e'),
    })

    helper.assert_refused({
        kind = 'invalid',
        message = 'неверное имя или пароль',
        code = 49,
        diagnostic = '80090308: LdapErr: DSID-0C09044E, data 52e',
    }, directory:authenticate('anna', 'wrong'))
end

g.test_a_password_the_directory_would_not_check_is_its_refusal = function()
    local directory = helper.connected({
        helper.bound(1),
        helper.anna(2),
        helper.done(2),
        helper.bound(3, 53, 'account locked'),
    })

    helper.assert_refused({
        kind = 'rejected',
        message = 'каталог ldaps://ldap.example.org не проверил пароль: код 53: account locked',
        code = 53,
        diagnostic = 'account locked',
    }, directory:authenticate('anna', 'anna-secret'))

    directory = helper.connected({ helper.bound(1), helper.anna(2), helper.done(2), helper.bound(3, 51, 'busy') })

    local _, err = directory:authenticate('anna', 'anna-secret')

    t.assert_equals(err.kind, 'unavailable')
end

g.test_a_name_with_two_entries_is_refused = function()
    local message =
        'каталог ldaps://ldap.example.org: имени отвечает больше одной записи — фильтр не однозначен'
    local directory, net = helper.connected({ helper.bound(1), helper.anna(2), helper.anna(2), helper.done(2) })

    helper.assert_refused({ kind = 'malformed', message = message }, directory:authenticate('anna', 'anna-secret'))
    t.assert_equals(#net.secured.written, 3)

    directory = helper.connected({ helper.bound(1), helper.anna(2), helper.done(2, 4) })
    helper.assert_refused({ kind = 'malformed', message = message }, directory:authenticate('anna', 'anna-secret'))
end

g.test_a_directory_that_sends_more_than_asked_is_malformed = function()
    local directory = helper.connected({ helper.bound(1), helper.anna(2), helper.anna(2), helper.anna(2) })

    helper.assert_refused({
        kind = 'malformed',
        message = 'каталог ldaps://ldap.example.org прислал больше 2 записей, чем просили',
    }, directory:authenticate('anna', 'anna-secret'))
end

g.test_references_are_not_followed = function()
    local directory, net = helper.connected({
        helper.bound(1),
        helper.reference(2),
        helper.anna(2),
        helper.reference(2),
        helper.done(2),
        helper.bound(3),
    })

    t.assert_equals(directory:authenticate('anna', 'anna-secret'), anna())
    t.assert_equals(#net.connected, 1)
end

g.test_a_failed_search_is_the_directory_refusal = function()
    local directory = helper.connected({ helper.bound(1), helper.done(2, 32, 'no such object') })

    helper.assert_refused({
        kind = 'rejected',
        message = 'каталог ldaps://ldap.example.org не нашёл записи: код 32: no such object',
        code = 32,
        diagnostic = 'no such object',
    }, directory:authenticate('anna', 'anna-secret'))
end

g.test_a_refused_service_account_stops_the_login = function()
    local directory, net = helper.connected({ helper.bound(1, 49, 'bad reader') })

    helper.assert_refused({
        kind = 'rejected',
        message = 'каталог ldaps://ldap.example.org не пустил служебную учётную запись: код 49: bad reader',
        code = 49,
        diagnostic = 'bad reader',
    }, directory:authenticate('anna', 'anna-secret'))
    t.assert_equals(#net.secured.written, 2)
    t.assert_equals(net.secured.closed, 1)
end

g.test_without_a_service_account_the_search_goes_first = function()
    local directory, net = helper.connected(
        { helper.anna(1), helper.done(1), helper.bound(2) },
        nil,
        { 'bind_dn', 'bind_password' }
    )

    t.assert_equals(directory:authenticate('anna', 'anna-secret'), anna())
    t.assert_equals(net.secured.written[1], search_request(1, uid('anna')))
end

g.test_attributes_are_matched_without_case = function()
    local entry = helper.entry(2, helper.DN, {
        { 'ENTRYUUID', { helper.UUID } },
        { 'displayname', { 'Анна' } },
        { 'memberof', { helper.GROUP, 'cn=admins,dc=example,dc=org' } },
        { 'objectClass', { 'person' } },
    })
    local directory, net = helper.connected({ helper.bound(1), entry, helper.done(2), helper.bound(3) }, {
        display = 'displayName',
        attributes = { 'memberOf', 'mail' },
    })
    local assertion = directory:authenticate('anna', 'anna-secret')

    t.assert_equals(assertion.name, 'Анна')
    t.assert_equals(assertion.claims, {
        dn = helper.DN,
        memberOf = { helper.GROUP, 'cn=admins,dc=example,dc=org' },
        mail = {},
    })
    t.assert_equals(
        net.secured.written[2],
        search_request(2, uid('anna'), { attributes = { 'entryUUID', 'displayName', 'memberOf', 'mail' } })
    )
end

g.test_an_entry_without_a_name_gives_none = function()
    local entry = helper.entry(2, helper.DN, { { 'entryUUID', { helper.UUID } } })
    local directory = helper.connected({ helper.bound(1), entry, helper.done(2), helper.bound(3) })
    local assertion = directory:authenticate('anna', 'anna-secret')

    t.assert_equals(assertion.name, nil)
    t.assert_equals(assertion.claims, { dn = helper.DN, memberOf = {} })
end

--- Вход с записью, у которой такой опознаватель.
local function login_with(attribute, values, overrides)
    local entry = helper.entry(2, helper.DN, { { attribute, values } })
    local directory = helper.connected({ helper.bound(1), entry, helper.done(2), helper.bound(3) }, overrides)

    return directory:authenticate('anna', 'anna-secret')
end

g.test_an_active_directory_guid_is_written_as_text = function()
    local raw = ''

    for byte = 1, 16 do
        raw = raw .. string.char(byte)
    end

    local assertion = login_with('objectGUID', { raw }, { subject = 'objectGUID' })

    t.assert_equals(assertion.subject, '04030201-0605-0807-090a-0b0c0d0e0f10')

    raw = string.char(0xE0, 0x04, 0x25, 0x3F, 0x89, 0x4F, 0xD3, 0x11, 0x9A, 0x0C, 0x03, 0x05, 0xE8, 0x2C, 0x33, 0x01)
    assertion = login_with('objectguid', { raw }, { subject = 'objectGUID' })
    t.assert_equals(assertion.subject, '3f2504e0-4f89-11d3-9a0c-0305e82c3301')
end

g.test_a_guid_of_wrong_length_is_malformed = function()
    helper.assert_refused({
        kind = 'malformed',
        message = ('запись %s: objectGUID в 15 байтах, а не в 16'):format(helper.DN),
    }, login_with('objectGUID', { string.rep('g', 15) }, { subject = 'objectGUID' }))
    helper.assert_refused({
        kind = 'malformed',
        message = ('запись %s: objectGUID в 17 байтах, а не в 16'):format(helper.DN),
    }, login_with('objectGUID', { string.rep('g', 17) }, { subject = 'objectGUID' }))
end

g.test_a_subject_must_fit_the_contract = function()
    local unfit = ('запись %s: entryUUID не годится в опознаватель: '):format(helper.DN)
        .. 'пусто, длиннее 255 байтов либо с управляющим знаком'

    t.assert_equals(helper.directory.MAX_SUBJECT, 255)
    t.assert_equals(login_with('entryUUID', { string.rep('u', 255) }).subject, string.rep('u', 255))
    t.assert_equals(login_with('entryUUID', { 'u' }).subject, 'u')
    helper.assert_refused({ kind = 'malformed', message = unfit }, login_with('entryUUID', { string.rep('u', 256) }))
    helper.assert_refused({ kind = 'malformed', message = unfit }, login_with('entryUUID', { '' }))
    helper.assert_refused({ kind = 'malformed', message = unfit }, login_with('entryUUID', { 'a\nb' }))
    helper.assert_refused({
        kind = 'malformed',
        message = ('запись %s: у записи нет атрибута entryUUID'):format(helper.DN),
    }, login_with('uid', { 'anna' }))
    helper.assert_refused({
        kind = 'malformed',
        message = ('запись %s: у записи нет атрибута entryUUID'):format(helper.DN),
    }, login_with('entryUUID', {}))
end

g.test_the_provider_is_the_directory_name = function()
    local directory = helper.connected({ helper.bound(1), helper.anna(2), helper.done(2), helper.bound(3) }, {
        name = 'corp',
    })

    t.assert_equals(directory:authenticate('anna', 'anna-secret').provider, 'corp')
end

g.test_the_search_is_given_what_is_left_of_the_deadline = function()
    local directory, net = helper.connected(
        { helper.bound(1), helper.anna(2), helper.done(2), helper.bound(3) },
        { timeout = 2.5 }
    )

    directory:authenticate('anna', 'anna-secret')
    t.assert_equals(net.secured.written[2], search_request(2, uid('anna'), { time = 3 }))
end

--- Часы планировщика: каждый вопрос — на шаг позже.
local function ticking(step)
    local now = 100 - step

    return function()
        now = now + step

        return now
    end
end

g.test_a_search_after_the_deadline_is_not_sent = function()
    local secured = helper.stream({ helper.bound(1) })

    helper.net(helper.stream({}), secured, { scheduler_now = ticking(1) })
    helper.wall()

    -- Вопросы к часам: соединение, TLS, отправка привязки, два чтения
    -- ответа — и пятый, перед поиском, уже на сроке.
    local directory = helper.ldap.new(helper.options({ timeout = 5 }))

    helper.assert_refused({
        kind = 'unavailable',
        message = 'каталог ldaps://ldap.example.org: не ответил за срок вызова',
    }, directory:authenticate('anna', 'anna-secret'))
    t.assert_equals(#secured.written, 2)
    t.assert_equals(secured.closed, 1)
end

--- Двойник, который перестаёт писать с записи номер `broken`.
local function failing_on(broken, chunks)
    local secured = helper.stream(chunks)
    local write = secured.write

    secured.write = function(self, data, timeout)
        if #self.written + 1 == broken then
            return nil, 'Broken pipe'
        end

        return write(self, data, timeout)
    end

    return secured
end

g.test_a_lost_connection_is_unavailable_at_every_step = function()
    local broken = {
        kind = 'unavailable',
        message = 'каталог ldaps://ldap.example.org: соединение оборвалось: Broken pipe',
    }
    local silent = {
        kind = 'unavailable',
        message = 'каталог ldaps://ldap.example.org: соединение оборвалось: сервер молчит',
    }
    local cases = {
        { failing_on(1, {}), broken },
        { failing_on(2, { helper.bound(1) }), broken },
        { failing_on(3, { helper.bound(1), helper.anna(2), helper.done(2) }), broken },
        { helper.stream({}), silent },
        { helper.stream({ helper.bound(1) }), silent },
        { helper.stream({ helper.bound(1), helper.anna(2) }), silent },
        { helper.stream({ helper.bound(1), helper.anna(2), helper.done(2) }), silent },
    }

    for _, case in ipairs(cases) do
        helper.net(helper.stream({}), case[1])
        helper.wall()
        helper.assert_refused(case[2], helper.ldap.new(helper.options()):authenticate('anna', 'anna-secret'))
        t.assert_equals(case[1].closed, 1)
    end
end

g.test_a_directory_that_cannot_be_reached_is_unavailable = function()
    helper.net(helper.stream({}), nil)
    helper.assert_refused({
        kind = 'unavailable',
        message = 'каталог ldaps://ldap.example.org: рукопожатие TLS не прошло: сертификат не принят',
    }, helper.ldap.new(helper.options()):authenticate('anna', 'anna-secret'))
end

--- Ограничитель-двойник: решает по листу и помнит ключи.
local function limiter_of(decisions)
    local limiter = { keys = {} }

    function limiter.consume(self, target)
        table.insert(self.keys, target.key)

        return unpack(table.remove(decisions, 1))
    end

    local limit = {
        by = function(_, key)
            return { key = key }
        end,
    }

    return limiter, limit
end

g.test_attempts_are_counted_before_the_directory = function()
    local limiter, limit = limiter_of({ { { allowed = true } } })
    local directory = helper.connected(
        { helper.bound(1), helper.anna(2), helper.done(2), helper.bound(3) },
        { limiter = limiter, limit = limit, name = 'corp' }
    )

    t.assert_equals(directory:authenticate('Anna.PETROVA', 'anna-secret').subject, helper.UUID)
    t.assert_equals(limiter.keys, { 'corp:anna.petrova' })
end

g.test_too_many_attempts_never_reach_the_directory = function()
    local limiter, limit = limiter_of({ { { allowed = false, retry_after = 12.2 } } })
    local directory, net = helper.connected({}, { limiter = limiter, limit = limit })

    helper.assert_refused({
        kind = 'throttled',
        message = 'попыток входа под этим именем больше предела: снова через 13 с',
        retry_after = 12.2,
    }, directory:authenticate('anna', 'anna-secret'))
    t.assert_equals(net.connected, {})
end

g.test_a_counter_that_does_not_answer_stops_the_login = function()
    local limiter, limit = limiter_of({ { nil, 'redis: connection refused' } })
    local directory, net = helper.connected({}, { limiter = limiter, limit = limit })

    helper.assert_refused({
        kind = 'unavailable',
        message = 'счёт попыток входа не ответил: redis: connection refused',
    }, directory:authenticate('anna', 'anna-secret'))
    t.assert_equals(net.connected, {})
end

g.test_an_empty_password_is_not_even_counted = function()
    local limiter, limit = limiter_of({})
    local directory = helper.connected({}, { limiter = limiter, limit = limit })

    helper.assert_refused(WRONG, directory:authenticate('anna', ''))
    t.assert_equals(limiter.keys, {})
end
