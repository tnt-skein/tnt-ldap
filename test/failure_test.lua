--- Проверки отказа: строкой, склейкой, в JSON; род по коду итога.

local json = require('json')
local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.ldap.failure')

local failure = helper.failure

g.test_a_refusal_reads_as_its_text = function()
    local outcome, err =
        failure.refuse(failure.REJECTED, 'каталог отказал', { code = 50, diagnostic = 'no access' })

    t.assert_equals(outcome, nil)
    t.assert_equals(err.kind, 'rejected')
    t.assert_equals(err.message, 'каталог отказал')
    t.assert_equals(err.code, 50)
    t.assert_equals(err.diagnostic, 'no access')
    t.assert_equals(tostring(err), 'каталог отказал')
    t.assert_equals('вход: ' .. err, 'вход: каталог отказал')
    t.assert_equals(err .. '!', 'каталог отказал!')
    t.assert_equals(json.encode({ err = err }), '{"err":"каталог отказал"}')
end

g.test_a_refusal_keeps_the_given_fields_apart = function()
    local fields = { retry_after = 30 }
    local _, err = failure.refuse(failure.THROTTLED, 'много попыток', fields)

    t.assert_equals(err.retry_after, 30)
    t.assert_equals(fields, { retry_after = 30 })

    local _, bare = failure.refuse(failure.INVALID, failure.WRONG)

    t.assert_equals({ kind = bare.kind, message = bare.message, code = bare.code }, {
        kind = 'invalid',
        message = 'неверное имя или пароль',
    })
end

g.test_kinds_are_named = function()
    t.assert_equals({
        helper.ldap.INVALID,
        helper.ldap.THROTTLED,
        helper.ldap.UNAVAILABLE,
        helper.ldap.REJECTED,
        helper.ldap.MALFORMED,
    }, { 'invalid', 'throttled', 'unavailable', 'rejected', 'malformed' })
end

g.test_a_result_is_unavailable_only_while_the_directory_is_busy = function()
    local kinds = {}

    for _, code in ipairs({ 1, 2, 3, 4, 32, 49, 50, 51, 52, 53, 80 }) do
        local _, err = failure.result({ code = code, diagnostic = 'd' }, 'поиск не удался')

        kinds[code] = err.kind
        t.assert_equals(err.message, ('поиск не удался: код %d: d'):format(code))
        t.assert_equals({ err.code, err.diagnostic }, { code, 'd' })
    end

    local _, bare = failure.result({ code = 32, diagnostic = '' }, 'поиск не удался')

    t.assert_equals({ bare.message, bare.diagnostic }, { 'поиск не удался: код 32', '' })
    t.assert_equals(kinds, {
        [1] = 'rejected',
        [2] = 'rejected',
        [3] = 'unavailable',
        [4] = 'rejected',
        [32] = 'rejected',
        [49] = 'rejected',
        [50] = 'rejected',
        [51] = 'unavailable',
        [52] = 'unavailable',
        [53] = 'rejected',
        [80] = 'rejected',
    })
end
