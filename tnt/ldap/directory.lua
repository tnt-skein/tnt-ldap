--- Каталог: вход паролем с удостоверением и поиск записей.
---
--- Вход — «найти, затем войти»: служебная учётная запись (или никто,
--- если каталог пускает искать без входа) ищет запись посетителя фильтром
--- из настроек, и пароль проверяет простая привязка по найденному DN.
--- DN из имени не собирается: у Active Directory, у каталога с людьми
--- в нескольких ветках и у входа по почте он не выводится из того, что
--- ввёл человек.
---
--- Порядок проверок держится на четырёх правилах:
---
--- 1. **Пустой пароль — отказ до каталога.** Простая привязка с DN
---    и пустым паролем — это привязка без проверки (RFC 4513, §5.1.2),
---    и каталог отвечает на неё успехом.
--- 2. **Счёт попыток — до каталога.** У каталога своя политика запирания,
---    и перебор со стороны узла запирал бы людей в самом каталоге. Ключ
---    счёта — имя в нижнем регистре: каталог сравнивает имена без учёта
---    регистра, и «Anna» с «ANNA» иначе считались бы порознь.
--- 3. **Имя в фильтр — только через `escape`** (RFC 4515, §3).
--- 4. **Пароль проверяется и у неизвестного имени**: привязкой к записи,
---    которой нет, — иначе ответ на неизвестное имя приходил бы на один
---    обмен раньше, и по времени было бы видно, какие имена в каталоге
---    есть. Отказ у обоих один — «неверное имя или пароль».
---
--- Удостоверение: `subject` — постоянный признак записи, `entryUUID`
--- (RFC 4530) либо `objectGUID` у Active Directory, а не DN: DN меняется
--- при переносе записи в другое подразделение. DN и атрибуты из настроек
--- (по умолчанию `memberOf`) лежат в `claims`, и роли из групп собирает
--- приложение, когда находит учётную запись по удостоверению. Личности
--- пакет не знает.

local clock = require('tnt.clock')
local external = require('tnt.external')
local must = require('tnt.must')
local utf8 = require('utf8')

local failure = require('tnt.ldap.failure')
local filter = require('tnt.ldap.filter')
local link = require('tnt.ldap.link')
local message = require('tnt.ldap.message')
local settings_of = require('tnt.ldap.settings')

local Module = {}

--- Самое длинное имя посетителя, байтов: длиннее — отказ до каталога.
Module.MAX_USERNAME = 256

--- Самый длинный опознаватель, байтов: предел `sub` OpenID Connect
--- (OpenID Connect Core 1.0, §2) — так опознаватели каталога и других
--- источников входа ложатся в один ключ учётной записи.
Module.MAX_SUBJECT = 255

--- Сколько записей самое большее отдаёт `search`, если не сказано иное.
Module.SIZE_LIMIT = 1000

--- Коды итога (RFC 4511, приложение A).
local SUCCESS = 0
local SIZE_LIMIT_EXCEEDED = 4
local INVALID_CREDENTIALS = 49

--- Записи, которой нет: к ней идёт привязка с паролем неизвестного имени.
local ABSENT = 'cn=tnt-ldap-absent,'

--- Атрибут опознавателя Active Directory: 16 байтов, а не текст.
local GUID = 'objectguid'

--- Чем доказан вход: паролем (RFC 8176).
local METHODS = { 'pwd' }

--- Ответы, которые годятся на привязку и на поиск.
local BOUND = { [message.BIND_RESPONSE] = true }
local FOUND = {
    [message.SEARCH_ENTRY] = true,
    [message.SEARCH_REFERENCE] = true,
    [message.SEARCH_DONE] = true,
}

--- Описание поиска.
local QUERY = {
    base = 'string',
    scope = { '?one_of', { 'base', 'one', 'sub' } },
    filter = 'not_empty',
    attributes = { '?array_of', 'not_empty' },
    size_limit = '?integer',
}

--- Внешняя зависимость: стенные часы — миг входа в удостоверении.
local source = external.install(Module, { now = clock.realtime })

---@class TntLdapAssertion Удостоверение: кто вошёл, через какой каталог и когда
---@field provider string Имя источника из настроек
---@field subject string Постоянный признак записи
---@field name string|nil Как каталог называет человека
---@field methods string[] Чем доказан вход: `pwd`
---@field authenticated_at number Миг входа, секунды стенных часов
---@field claims table DN и атрибуты из настроек: имя — список значений

---@class TntLdapEntry Запись каталога
---@field dn string
---@field attributes table<string, string[]> Имя атрибута — значения

---@class TntLdapQuery Поиск
---@field base string С какой записи искать
---@field scope string|nil base, one либо sub; по умолчанию sub
---@field filter string Фильтр строкой; значения от людей — через `ldap.escape`
---@field attributes string[]|nil Какие атрибуты вернуть; пусто — все обычные
---@field size_limit integer|nil Сколько записей самое большее; по умолчанию 1000

---@class TntLdapDirectory Клиент одного каталога
---@field name string Имя источника
---@field settings TntLdapSettings
local Directory = {}
Directory.__index = Directory

--- Заводит клиент каталога. В сеть не ходит.
---@param options TntLdapOptions
---@return TntLdapDirectory
function Module.new(options)
    local settings = settings_of.check(options, 3)

    return setmetatable({ name = settings.name, settings = settings }, Directory)
end

--- Привязка: ответ каталога с итогом как есть.
---@param connection TntLdapLink
---@param dn string
---@param password string
---@param deadline number
---@return TntLdapMessage|nil answer
---@return TntLdapFailure|nil err
local function bind(connection, dn, password, deadline)
    local id, err = link.request(connection, function(number)
        return message.bind(number, dn, password)
    end, deadline)

    if id == nil then
        return nil, err
    end

    return link.answer(connection, id, BOUND, deadline)
end

--- Вход служебной учётной записью, если она названа.
---@param connection TntLdapLink
---@param settings TntLdapSettings
---@param deadline number
---@return boolean|nil entered
---@return TntLdapFailure|nil err
local function enter(connection, settings, deadline)
    if settings.bind_dn == nil then
        return true
    end

    local answer, err = bind(connection, settings.bind_dn, settings.bind_password --[[@as string]], deadline)

    if answer == nil then
        return nil, err
    end

    if answer.code ~= SUCCESS then
        return failure.result(
            answer,
            ('каталог %s не пустил служебную учётную запись'):format(
                settings.where
            )
        )
    end

    return true
end

--- Поиск: записи и ответ с итогом.
---
--- Ссылки на другие каталоги пропускаются: ходить по ним значило бы
--- нести пароль туда, куда его не собирались нести. Срок поиска каталогу —
--- остаток срока вызова: дальше его ответ всё равно никто не ждёт.
---@param connection TntLdapLink
---@param request TntLdapSearchRequest Без `time_limit`: его назначает срок
---@param deadline number
---@return TntLdapMessage[]|nil entries
---@return TntLdapMessage|TntLdapFailure|nil done Итог либо отказ
local function search(connection, request, deadline)
    local left, late = link.remaining(connection.where, deadline)

    if left == nil then
        return nil, late
    end

    request.time_limit = math.ceil(left)

    local id, err = link.request(connection, function(number)
        return message.search(number, request)
    end, deadline)

    if id == nil then
        return nil, err
    end

    local entries = {}

    while true do
        local answer, lost = link.answer(connection, id, FOUND, deadline)

        if answer == nil then
            return nil, lost
        end

        if answer.tag == message.SEARCH_DONE then
            return entries, answer
        end

        if answer.tag == message.SEARCH_ENTRY then
            if #entries == request.size_limit then
                return failure.refuse(
                    failure.MALFORMED,
                    ('каталог %s прислал больше %d записей, чем просили'):format(
                        connection.where,
                        request.size_limit
                    )
                )
            end

            table.insert(entries, answer)
        end
    end
end

--- Соединение на одно дело: открыть, войти служебной учётной записью,
--- сделать, закрыть в любом исходе.
---@param directory TntLdapDirectory
---@param work fun(connection: TntLdapLink, deadline: number): any, any
---@return any result
---@return TntLdapFailure|nil err
local function within(directory, work)
    local settings = directory.settings
    local deadline = link.deadline(settings.timeout)
    local connection, err = link.open(settings, deadline)

    if connection == nil then
        return nil, err
    end

    local result, refusal = enter(connection, settings, deadline)

    if result then
        result, refusal = work(connection, deadline)
    end

    link.close(connection)

    return result, refusal
end

--- Атрибуты записи по именам: названные — под своим именем, как их
--- назвал вызывающий, прочие — как их назвал каталог.
---
--- Имена атрибутов в LDAP регистра не различают (RFC 4512, §2.5),
--- и каталог вправе ответить `memberof` на просьбу о `memberOf`.
---@param entry TntLdapMessage
---@param wanted string[]
---@return table<string, string[]>
local function keyed(entry, wanted)
    local names = {}

    for _, name in ipairs(wanted) do
        names[name:lower()] = name
    end

    local attributes = {}

    for _, attribute in
        ipairs(entry.attributes --[[@as TntLdapAttribute[] ]])
    do
        attributes[names[attribute.type:lower()] or attribute.type] = attribute.values
    end

    return attributes
end

--- Опознаватель Active Directory текстом: `objectGUID` — 16 байтов, первые
--- три поля — младшим байтом вперёд.
---@param raw string
---@return string
local function guid(raw)
    return ('%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x'):format(
        raw:byte(4),
        raw:byte(3),
        raw:byte(2),
        raw:byte(1),
        raw:byte(6),
        raw:byte(5),
        raw:byte(8),
        raw:byte(7),
        raw:byte(9),
        raw:byte(10),
        raw:byte(11),
        raw:byte(12),
        raw:byte(13),
        raw:byte(14),
        raw:byte(15),
        raw:byte(16)
    )
end

--- Опознаватель записи либо текст, почему его нет.
---@param attribute string Имя атрибута опознавателя
---@param values string[]|nil Его значения
---@return string|nil subject
---@return string|nil why
local function subject_of(attribute, values)
    local value = (values or {})[1] --[[@as string|nil]]

    if value == nil then
        return nil, ('у записи нет атрибута %s'):format(attribute)
    end

    if attribute:lower() == GUID then
        if #value ~= 16 then
            return nil, ('%s в %d байтах, а не в 16'):format(attribute, #value)
        end

        value = guid(value)
    end

    if #value == 0 or #value > Module.MAX_SUBJECT or value:find('%c') then
        return nil,
            ('%s не годится в опознаватель: пусто, длиннее %d байтов либо с управляющим знаком'):format(
                attribute,
                Module.MAX_SUBJECT
            )
    end

    return value
end

--- Удостоверение из найденной записи.
---@param settings TntLdapSettings
---@param entry TntLdapMessage
---@return TntLdapAssertion|nil assertion
---@return TntLdapFailure|nil err
local function assertion_of(settings, entry)
    local wanted = { settings.subject, settings.display }

    for _, name in ipairs(settings.attributes) do
        table.insert(wanted, name)
    end

    local attributes = keyed(entry, wanted)
    local subject, why = subject_of(settings.subject, attributes[settings.subject])

    if subject == nil then
        return failure.refuse(failure.MALFORMED, ('запись %s: %s'):format(entry.dn, why))
    end

    ---@type table<string, string|string[]>
    local claims = {
        dn = entry.dn --[[@as string]],
    }

    for _, name in ipairs(settings.attributes) do
        claims[name] = attributes[name] or {}
    end

    return {
        provider = settings.name,
        subject = subject,
        name = (attributes[settings.display] or {})[1],
        methods = table.copy(METHODS),
        authenticated_at = source().now(),
        claims = claims,
    }
end

--- Вход: поиск записи по имени и привязка её DN с паролем.
---@param connection TntLdapLink
---@param settings TntLdapSettings
---@param username string
---@param password string
---@param deadline number
---@return TntLdapAssertion|nil assertion
---@return TntLdapFailure|nil err
local function login(connection, settings, username, password, deadline)
    local escaped = filter.escape(username)
    local text = settings.filter:gsub(settings_of.USERNAME, function()
        return escaped
    end)
    -- Фильтр разобран при сборке, а экранированное имя — только значение:
    -- отказать разбор здесь не может.
    local encoded = assert(filter.encode(text))
    local entries, done = search(connection, {
        base = settings.base,
        scope = settings.scope,
        filter = encoded,
        attributes = { settings.subject, settings.display, unpack(settings.attributes) },
        -- Двух записей хватает, чтобы узнать, что имя не однозначно.
        size_limit = 2,
    }, deadline)

    if entries == nil then
        return nil, done --[[@as TntLdapFailure]]
    end

    ---@cast done TntLdapMessage
    if done.code == SIZE_LIMIT_EXCEEDED or #entries > 1 then
        return failure.refuse(
            failure.MALFORMED,
            ('каталог %s: имени отвечает больше одной записи — фильтр не однозначен'):format(
                settings.where
            )
        )
    end

    if done.code ~= SUCCESS then
        return failure.result(done, ('каталог %s не нашёл записи'):format(settings.where))
    end

    local entry = entries[1]
    local answer, err = bind(connection, entry and entry.dn or ABSENT .. settings.base, password, deadline)

    if answer == nil then
        return nil, err
    end

    if entry == nil or answer.code == INVALID_CREDENTIALS then
        return failure.refuse(failure.INVALID, failure.WRONG, { code = answer.code, diagnostic = answer.diagnostic })
    end

    if answer.code ~= SUCCESS then
        return failure.result(answer, ('каталог %s не проверил пароль'):format(settings.where))
    end

    return assertion_of(settings, entry)
end

--- Считает попытку входа, пока каталог о ней не знает.
---
--- Отказ счёта — `unavailable`, а не пропуск: вход без счёта и есть
--- то, от чего счёт стоит перед каталогом.
---@param settings TntLdapSettings
---@param username string
---@return boolean|nil counted
---@return TntLdapFailure|nil err
local function count(settings, username)
    local limiter = settings.limiter

    if limiter == nil then
        return true
    end

    local key = ('%s:%s'):format(settings.name, utf8.lower(username))
    local decision, err = limiter:consume((settings.limit --[[@as table]]):by(key))

    if decision == nil then
        return failure.refuse(
            failure.UNAVAILABLE,
            ('счёт попыток входа не ответил: %s'):format(tostring(err))
        )
    end

    if not decision.allowed then
        local text = ('попыток входа под этим именем больше предела: снова через %d с'):format(
            math.ceil(decision.retry_after)
        )

        return failure.refuse(failure.THROTTLED, text, { retry_after = decision.retry_after })
    end

    return true
end

--- Вход паролем: удостоверение либо отказ.
---
---     local assertion, err = directory:authenticate('anna', password)
---     --> { provider = 'ldap', subject = '8a14f830-…', name = 'Анна Петрова',
---     -->   methods = { 'pwd' }, authenticated_at = 1790000000.25,
---     -->   claims = { dn = 'uid=anna,ou=people,dc=example,dc=org', memberOf = { … } } }
---@param username string
---@param password string
---@return TntLdapAssertion|nil assertion
---@return TntLdapFailure|nil err
function Directory:authenticate(username, password)
    local caller = must.at(2)

    caller.string(username, 'имя')
    caller.string(password, 'пароль')

    if username == '' or #username > Module.MAX_USERNAME or password == '' then
        return failure.refuse(failure.INVALID, failure.WRONG)
    end

    local settings = self.settings
    local counted, refused = count(settings, username)

    if not counted then
        return nil, refused
    end

    local assertion, err = within(self, function(connection, deadline)
        return login(connection, settings, username, password, deadline)
    end)

    return assertion, err
end

--- Поиск записей от имени служебной учётной записи.
---
---     directory:search({
---         base = 'ou=groups,dc=example,dc=org',
---         filter = '(member=' .. ldap.escape(dn) .. ')',
---         attributes = { 'cn' },
---     })
---     --> { { dn = 'cn=operators,ou=groups,dc=example,dc=org', attributes = { cn = { 'operators' } } } }
---@param query TntLdapQuery
---@return TntLdapEntry[]|nil entries
---@return TntLdapFailure|nil err
function Directory:search(query)
    local caller = must.at(2)

    caller.options(query, 'поиск', QUERY)
    caller.optional.positive(query.size_limit, 'поиск.size_limit')

    local encoded, wrong = filter.encode(query.filter)

    if encoded == nil then
        error(('поиск.filter: %s'):format(wrong), 2)
    end

    local wanted = query.attributes or {}
    local settings = self.settings
    local entries, err = within(self, function(connection, deadline)
        local found, done = search(connection, {
            base = query.base,
            scope = query.scope or settings_of.SCOPE,
            filter = encoded,
            attributes = wanted,
            size_limit = query.size_limit or Module.SIZE_LIMIT,
        }, deadline)

        local answer = done --[[@as TntLdapMessage]]

        if found ~= nil and answer.code ~= SUCCESS then
            return failure.result(answer, ('каталог %s не выполнил поиск'):format(settings.where))
        end

        return found, done
    end)

    if entries == nil then
        return nil, err
    end

    local shaped = {}

    for _, entry in ipairs(entries) do
        table.insert(shaped, { dn = entry.dn, attributes = keyed(entry, wanted) })
    end

    return shaped
end

return Module
