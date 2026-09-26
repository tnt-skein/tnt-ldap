#!/usr/bin/env bash
# Поднимает каталог OpenLDAP для живых проверок клиента tnt-ldap.
#
# Настоящий каталог, а не двойник: двойник показывает, что мы правильно
# разговариваем сами с собой, а slapd — что нас понимает кто-то ещё.
# Разница вылезает на мелочах, которых не видно в стандарте: как каталог
# называет атрибуты в ответе, чем отвечает на привязку к записи, которой
# нет, что отдаёт на StartTLS.
#
# Один контейнер, два порта: 636 — TLS с первого байта (ldaps://), 389 —
# открытый, и клиент переходит на нём на TLS просьбой StartTLS. Сертификат
# выпускается здесь же на сутки корнем из того же каталога, на адрес
# 127.0.0.1; клиентского сертификата каталог не требует
# (LDAP_TLS_VERIFY_CLIENT=never): tnt-tls его не предъявляет.
#
# Учётные записи: служебная cn=readonly,dc=example,dc=org (только чтение),
# anna — в группе operators, и двое людей с одним cn «Двойник» — для
# отказа по неоднозначному имени. memberOf каталог ведёт сам.
#
# Каталог сертификатов — LDAP_TLS_DIR, по умолчанию
# test/stand/run/ldap-tls; живая проверка читает ту же переменную.
#
#   test/stand/ldap.sh          # поднять
#   test/stand/ldap.sh stop     # погасить
set -euo pipefail

# Относительный каталог отсчитывается от места запуска: оттуда его
# читает и живая проверка. Ниже сценарий переходит в свой каталог, и без
# этого стенд лёг бы в одно место, а проверка искала бы его в другом.
case "${LDAP_TLS_DIR:-}" in
    '' | /*) ;;
    *) LDAP_TLS_DIR="${PWD}/${LDAP_TLS_DIR}" ;;
esac

cd "$(dirname "$0")"

IMAGE='osixia/openldap:1.5.0'
CONTAINER='tnt-stand-ldap'
PORT="${STAND_LDAP_PORT:-18389}"
TLS_PORT="${STAND_LDAP_TLS_PORT:-18636}"
DIR="${LDAP_TLS_DIR:-run/ldap-tls}"

# Пароли стенда: локальный каталог для проверок, а не развёртывание.
ADMIN_PASSWORD='admin-secret'
READER_PASSWORD='reader-secret'

if ! command -v docker > /dev/null 2>&1; then
    echo 'docker не найден: каталог поднять нечем' >&2
    exit 1
fi

if [ "${1:-up}" = 'stop' ]; then
    docker rm -f "${CONTAINER}" > /dev/null 2>&1 || true
    echo 'каталог остановлен'
    exit 0
fi

if ! command -v openssl > /dev/null 2>&1; then
    echo 'openssl не найден: сертификаты выпустить нечем' >&2
    exit 1
fi

mkdir -p "${DIR}"
DIR="$(cd "${DIR}" && pwd)"

# Сертификаты выпускаются заново на каждый подъём: срок у них сутки,
# и вчерашний каталог дал бы отказ рукопожатия, неотличимый от того,
# ради которого проверка написана.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=tnt-ldap-live-ca' \
    -keyout "${DIR}/ca.key" -out "${DIR}/ca.pem" 2> /dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > "${DIR}/server.ext"
openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' \
    -keyout "${DIR}/server.key" -out "${DIR}/server.csr" 2> /dev/null
openssl x509 -req -in "${DIR}/server.csr" -days 1 \
    -CA "${DIR}/ca.pem" -CAkey "${DIR}/ca.key" -CAcreateserial \
    -extfile "${DIR}/server.ext" -out "${DIR}/server.pem" 2> /dev/null

# Параметры DH образ выпускает сам, если их нет, — новым «безопасным
# простым», и это минуты. Готовая группа ffdhe2048 (RFC 7919) — мгновенно,
# а параметры -dsaparam slapd образа не принимает.
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out "${DIR}/dhparam.pem" 2> /dev/null

# slapd в образе запускается не от root: ключ должен читаться всеми.
chmod 644 "${DIR}"/*.key

# Повторный запуск безвреден: контейнер с тем же именем сносится
# и поднимается заново. Данных на диск хозяина стенд не пишет.
docker rm -f "${CONTAINER}" > /dev/null 2>&1 || true

# --copy-service: образ правит права на сертификаты у себя, а не в каталоге
# хозяина.
docker run -d \
    --name "${CONTAINER}" \
    -p "127.0.0.1:${PORT}:389" \
    -p "127.0.0.1:${TLS_PORT}:636" \
    -e LDAP_DOMAIN=example.org \
    -e LDAP_ADMIN_PASSWORD="${ADMIN_PASSWORD}" \
    -e LDAP_READONLY_USER=true \
    -e LDAP_READONLY_USER_USERNAME=readonly \
    -e LDAP_READONLY_USER_PASSWORD="${READER_PASSWORD}" \
    -e LDAP_TLS=true \
    -e LDAP_TLS_CRT_FILENAME=server.pem \
    -e LDAP_TLS_KEY_FILENAME=server.key \
    -e LDAP_TLS_CA_CRT_FILENAME=ca.pem \
    -e LDAP_TLS_DH_PARAM_FILENAME=dhparam.pem \
    -e LDAP_TLS_VERIFY_CLIENT=never \
    -v "${DIR}:/container/service/slapd/assets/certs" \
    "${IMAGE}" --copy-service > /dev/null

# Готовности ждём: проверки, запущенные сразу после подъёма, иначе
# пропустятся — и это выглядит как «всё хорошо», хотя ничего
# не проверено. Готов — это не «отвечает»: при первом подъёме образ
# настраивает каталог временным slapd и затем перезапускает его. Ждём
# боевого slapd и ответа по ldaps://, который появляется последним.
ready=0

for _ in $(seq 1 120); do
    if docker logs "${CONTAINER}" 2>&1 | grep -q 'Running /container/run/process/slapd/run' \
        && docker exec -e LDAPTLS_REQCERT=never "${CONTAINER}" ldapsearch -x -H ldaps://127.0.0.1 \
            -b dc=example,dc=org -s base -D cn=admin,dc=example,dc=org -w "${ADMIN_PASSWORD}" > /dev/null 2>&1; then
        ready=1
        break
    fi

    sleep 0.5
done

if [ "${ready}" -ne 1 ]; then
    echo "каталог не ответил за минуту: смотрите docker logs ${CONTAINER}" >&2
    exit 1
fi

docker exec -i "${CONTAINER}" ldapadd -x -H ldap://127.0.0.1 \
    -D cn=admin,dc=example,dc=org -w "${ADMIN_PASSWORD}" > /dev/null << 'LDIF'
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: uid=anna,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: anna
cn: Анна Петрова
sn: Петрова
mail: anna@example.org
userPassword: anna-secret

dn: uid=twin1,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: twin1
cn: Двойник
sn: Первый
userPassword: twin-secret

dn: uid=twin2,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: twin2
cn: Двойник
sn: Второй
userPassword: twin-secret

dn: cn=operators,ou=groups,dc=example,dc=org
objectClass: groupOfUniqueNames
cn: operators
uniqueMember: uid=anna,ou=people,dc=example,dc=org
LDIF

echo "каталог поднят: ldaps://127.0.0.1:${TLS_PORT}, ldap://127.0.0.1:${PORT} (StartTLS), сертификаты в ${DIR}"
