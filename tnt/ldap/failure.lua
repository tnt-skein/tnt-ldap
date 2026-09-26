--- Отказ клиента каталога: род, текст и то, что ответил каталог.
---
--- Вход паролем в каталог срывается по причинам, которые приходят
--- снаружи: неверный пароль, каталог лежит, служебная учётная запись
--- отозвана. Это «так бывает», а не ошибка программиста, — отказ парой
--- `nil, err`. Вызывающему нужен род — слово, по которому решают, что
--- отвечать посетителю:
---
--- * `invalid` — имя или пароль не приняты: пустой пароль, имени нет
---   в каталоге, каталог ответил `invalidCredentials`;
--- * `throttled` — попыток по этому имени больше предела: счёт идёт
---   до каталога, и каталог о них не узнал;
--- * `unavailable` — каталог не ответил либо занят: сеть, TLS, срок,
---   `busy`, `unavailable`; лечит время, а не посетитель;
--- * `rejected` — каталог отказал в служебном действии: служебная
---   учётная запись не вошла, поиска нет, прав на него нет;
--- * `malformed` — ответ не годится: не по RFC 4511, имени отвечает
---   больше одной записи, у записи нет опознавателя.
---
--- Роды разведены ради ответа посетителю: `invalid` — 401, `throttled` —
--- 429 с `Retry-After`, остальные — 503. Сбой каталога — не неверный
--- пароль: 401 отправил бы человека вводить пароль заново, а счёт попыток
--- засчитал бы ему чужую беду.
---
--- Текст отказа `invalid` один на все его причины — «неверное имя или
--- пароль»: по слову иначе было бы видно, какие имена в каталоге есть.
--- Что сказал каталог, лежит отдельно, в полях `code` и `diagnostic`,
--- для журнала оператора. Строкой отказ читается целиком: `tostring(err)`,
--- склейка и `json.encode` дают его текст.

local Module = {}

--- Имя или пароль не приняты.
Module.INVALID = 'invalid'

--- Попыток больше предела.
Module.THROTTLED = 'throttled'

--- Каталог не ответил либо занят.
Module.UNAVAILABLE = 'unavailable'

--- Каталог отказал в служебном действии.
Module.REJECTED = 'rejected'

--- Ответ каталога не годится.
Module.MALFORMED = 'malformed'

--- Текст отказа `invalid` — один на все его причины.
Module.WRONG = 'неверное имя или пароль'

---@class TntLdapFailure Отказ клиента каталога
---@field kind string Род: invalid, throttled, unavailable, rejected либо malformed
---@field message string Что не так — его и отдаёт `tostring`
---@field code integer|nil Код итога LDAP (`resultCode`), если каталог его назвал
---@field diagnostic string|nil Пояснение каталога (`diagnosticMessage`)
---@field retry_after number|nil Секунды до новой попытки — у `throttled`

--- Текст отказа: им отказ читается строкой, в склейке и в JSON.
---@param refusal TntLdapFailure
---@return string
local function text_of(refusal)
    return refusal.message
end

--- Поведение всех отказов пакета.
local FAILURE = {
    __tostring = text_of,
    __serialize = text_of,
    __concat = function(before, after)
        return tostring(before) .. tostring(after)
    end,
}

--- Коды итога, которые значат «каталог занят или не успел», а не «отказал»
--- (RFC 4511, приложение A): `timeLimitExceeded`, `busy`, `unavailable`.
--- Их лечит время, и посетителю незачем слышать о них как об отказе.
local TRANSIENT = { [3] = true, [51] = true, [52] = true }

--- Отказ парой: `nil` и таблица с родом, текстом и полями каталога.
---@param kind string Род — одна из констант модуля
---@param message string
---@param fields table|nil Код итога, пояснение каталога, срок новой попытки
---@return nil
---@return TntLdapFailure
function Module.refuse(kind, message, fields)
    local refusal = table.copy(fields or {})

    refusal.kind = kind
    refusal.message = message

    return nil, setmetatable(refusal, FAILURE)
end

--- Отказ по итогу операции, которую каталог не выполнил.
---
--- Род — `unavailable` у кодов «занят» и «не успел», иначе `rejected`;
--- код и пояснение каталога — в тексте и в полях отказа.
---@param answer TntLdapMessage Ответ с итогом
---@param text string Что не удалось — начало текста
---@return nil
---@return TntLdapFailure
function Module.result(answer, text)
    local kind = TRANSIENT[answer.code] and Module.UNAVAILABLE or Module.REJECTED
    -- Пояснение каталог шлёт не всегда, и пустое не дописывается.
    local explained = answer.diagnostic == '' and '' or ': ' .. answer.diagnostic
    local message = ('%s: код %d%s'):format(text, answer.code, explained)

    return Module.refuse(kind, message, { code = answer.code, diagnostic = answer.diagnostic })
end

return Module
