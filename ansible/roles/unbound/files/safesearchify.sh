#!/bin/bash

# This can be whereever your unbound config storage is. You will have to use include: option inside the main unbound.conf though.
FILE="/etc/unbound/unbound.conf.d/safesearch.conf"

if [ $UID != "0" ]; then
    echo "This script must be run as root!"
    exit 1
fi

echo "server:" > "${FILE}"

# Google
echo "    # Google Safesearch" >> "${FILE}"
URL="https://www.google.com/supported_domains"
DOMAINS="$(curl -s $URL 2>/dev/null)"
for DOMAIN in $DOMAINS; do
    DOMAIN=$(echo $DOMAIN | cut -c 2-)
    printf '    local-zone: "%s" redirect \n' "$DOMAIN" >> "${FILE}"
    printf '    local-data: "%s CNAME forcesafesearch.google.com" \n' "$DOMAIN" >> "${FILE}"
done

# Youtube
echo >> "${FILE}"
echo "    # Youtube Restricted" >> "${FILE}"
DOMAIN=youtube
printf '    local-zone: "%s.com" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%s.com CNAME restrictmoderate.%s.com" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"
printf '    local-zone: "%si.com" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%si.com CNAME restrictmoderate.%s.com" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"
printf '    local-zone: "%si.googleapis.com" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%si.googleapis.com CNAME restrictmoderate.%s.com" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"
printf '    local-zone: "%s.googleapis.com" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%s.googleapis.com CNAME restrictmoderate.%s.com" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"
printf '    local-zone: "%s-nocookie.com" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%s-nocookie.com CNAME restrictmoderate.%s.com" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"


# DuckDuckGo
echo >> "${FILE}"
echo "    # DuckDuckGo Safe" >> "${FILE}"
DOMAIN=duckduckgo.com
printf '    local-zone: "%s" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%s CNAME safe.%s" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"
printf '    local-zone: "duck.com" redirect \n' >> "${FILE}"
printf '    local-data: "duck.com CNAME safe.%s" \n' "$DOMAIN" >> "${FILE}"

# Bing
echo >> "${FILE}"
echo "    # Bing Strict" >> "${FILE}"
DOMAIN=bing.com
printf '    local-zone: "%s" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%s CNAME strict.%s" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"

# Qwant
echo >> "${FILE}"
echo "    # Qwant SafeAPI" >> "${FILE}"
DOMAIN=qwant.com
printf '    local-zone: "%s" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%s CNAME safeapi.%s" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"

# Pixabay
echo >> "${FILE}"
echo "    # Pixabay Safesearch" >> "${FILE}"
DOMAIN=pixabay.com
printf '    local-zone: "%s" redirect \n' "$DOMAIN" >> "${FILE}"
printf '    local-data: "%s CNAME safesearch.%s" \n' "$DOMAIN" "$DOMAIN" >> "${FILE}"

# Yandex
echo >> "${FILE}"
echo "    # Yandex FamliySearch" >> "${FILE}"
for YANDEX in com ru ua by kz; do
    printf '    local-zone: "yandex.%s" redirect \n' "$YANDEX" >> "${FILE}"
    printf '    local-data: "yandex.%s CNAME familysearch.yandex.ru" \n' "$YANDEX" >> "${FILE}"
done
