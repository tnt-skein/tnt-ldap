rockspec_format = '3.0'

package = 'tnt-ldap'
version = 'scm-1'

source = {
    url = 'git+https://github.com/tnt-skein/tnt-ldap.git',
    branch = 'main',
}

description = {
    summary = 'Клиент каталога LDAP: вход паролем с удостоверением и поиск записей под TLS',
    detailed = [[
        LDAPv3 (RFC 4511) поверх сокета Tarantool: свой BER, фильтр
        строкой по RFC 4515 с разбором в запись каталога, простая
        привязка паролем, поиск. TLS всегда: ldaps:// с первого байта
        либо ldap:// со StartTLS через tnt-tls; открытого разговора нет.
        Один срок на вызов по монотонным часам, сообщение каталога
        не длиннее мегабайта, разбор ответа строгий.

        Вход паролем — «найти, затем войти»: пустой пароль — отказ
        до каталога, счёт попыток по имени — до каталога ограничителем,
        который приходит настройкой, имя в фильтре экранировано, пароль
        неизвестного имени тоже уходит в каталог. Удостоверение:
        provider из настроек, subject — entryUUID либо objectGUID, name,
        methods = pwd, claims — DN и атрибуты из настроек (memberOf).
        Личности пакет не знает: учётную запись по удостоверению
        находит приложение.

        Отказ — пара с родом: invalid, throttled, unavailable, rejected,
        malformed. Зависит от tnt-tls (шифрование), tnt-clock (часы),
        tnt-external (подмена сети и часов в проверках) и tnt-must
        (проверки аргументов).
    ]],
    homepage = 'https://github.com/tnt-skein/tnt-ldap',
    issues_url = 'https://github.com/tnt-skein/tnt-ldap/issues',
    maintainer = 'tnt-skein',
    license = 'MIT',
    labels = { 'tarantool', 'ldap', 'active-directory', 'authentication', 'directory' },
}

dependencies = {
    'lua >= 5.1',
    -- Проверки настроек и аргументов на строке вызывающего.
    'tnt-must',
    -- Монотонные часы срока и стенные — миг входа.
    'tnt-clock',
    -- Подмена сети, TLS и часов в проверках.
    'tnt-external',
    -- TLS поверх сокета: ldaps:// и StartTLS.
    'tnt-tls',
}

build = {
    type = 'builtin',
    modules = {
        ['tnt.ldap'] = 'tnt/ldap.lua',
        ['tnt.ldap.ber'] = 'tnt/ldap/ber.lua',
        ['tnt.ldap.directory'] = 'tnt/ldap/directory.lua',
        ['tnt.ldap.failure'] = 'tnt/ldap/failure.lua',
        ['tnt.ldap.filter'] = 'tnt/ldap/filter.lua',
        ['tnt.ldap.link'] = 'tnt/ldap/link.lua',
        ['tnt.ldap.message'] = 'tnt/ldap/message.lua',
        ['tnt.ldap.settings'] = 'tnt/ldap/settings.lua',
    },
}
