#!/usr/bin/env bash
#
# usage update-blacklist.sh <configuration file>
# eg: update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf
#

IPSET_NAME_PREFIX=blacklist
IPSET_NAME_V4="${IPSET_NAME_PREFIX}_v4"
IPSET_NAME_V6="${IPSET_NAME_PREFIX}_v6"
IPV4_REGEX="(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?"
IPV6_REGEX="(?:(?:[0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|\
(?:[0-9a-f]{1,4}:){1,7}:|\
(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|\
(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|\
(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|\
(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|\
(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|\
[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|\
:(?:(?::[0-9a-f]{1,4}){1,7}|:)|\
::(?:[f]{4}(?::0{1,4})?:)?\
(?:(25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3,3}\
(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|\
(?:[0-9a-f]{1,4}:){1,4}:\
(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3,3}\
(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))\
(?:/[0-9]{1,3})?"

function exists() { command -v "$1" >/dev/null 2>&1 ; }

if [[ -z "$1" ]]; then
  echo "Error: please specify a configuration file, e.g. $0 /etc/ipset-blacklist/ipset-blacklist.conf"
  exit 1
fi

# shellcheck source=ipset-blacklist.conf
if ! source "$1"; then
  echo "Error: can't load configuration file $1"
  exit 1
fi

if ! exists curl && exists egrep && exists grep && exists ipset && exists iptables && exists sed && exists sort && exists wc ; then
  echo >&2 "Error: searching PATH fails to find executables among: curl egrep grep ipset iptables sed sort wc"
  exit 1
fi

DO_OPTIMIZE_CIDR=no
if exists cidr-merger && [[ ${OPTIMIZE_CIDR:-yes} != no ]]; then
  DO_OPTIMIZE_CIDR=yes
fi

if [[ ! -d $(dirname "$IP_BLACKLIST") || ! -d $(dirname "$IP_BLACKLIST_RESTORE") ]]; then
  echo >&2 "Error: missing directory(s): $(dirname "$IP_BLACKLIST" "$IP_BLACKLIST_RESTORE"|sort -u)"
  exit 1
fi

if [[ ! -d $(dirname "$IP6_BLACKLIST") || ! -d $(dirname "$IP6_BLACKLIST_RESTORE") ]]; then
  echo >&2 "Error: missing directory(s): $(dirname "$IP6_BLACKLIST" "$IP6_BLACKLIST_RESTORE"|sort -u)"
  exit 1
fi

# create the ipset if needed (or abort if does not exists and FORCE=no)
if ! ipset list -n|command grep -q "$IPSET_NAME_V4"; then
  if [[ ${FORCE:-no} != yes ]]; then
    echo >&2 "Error: ipset does not exist yet, add it using:"
    echo >&2 "# ipset create $IPSET_NAME_V4 -exist hash:net family inet hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}"
    exit 1
  fi
  if ! ipset create "$IPSET_NAME_V4" -exist hash:net family inet hashsize "${HASHSIZE:-16384}" maxelem "${MAXELEM:-65536}"; then
    echo >&2 "Error: while creating the initial ipset"
    exit 1
  fi
fi

# create the ipset if needed (or abort if does not exists and FORCE=no)
if ! ipset list -n|command grep -q "$IPSET_NAME_V6"; then
  if [[ ${FORCE:-no} != yes ]]; then
    echo >&2 "Error: ipset does not exist yet, add it using:"
    echo >&2 "# ipset create $IPSET_NAME_V6 -exist hash:net family inet6 hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}"
    exit 1
  fi
  if ! ipset create "$IPSET_NAME_V6" -exist hash:net family inet6 hashsize "${HASHSIZE:-16384}" maxelem "${MAXELEM:-65536}"; then
    echo >&2 "Error: while creating the initial ipset"
    exit 1
  fi
fi

# create the iptables binding if needed (or abort if does not exists and FORCE=no)
if ! iptables -nvL | command grep -q "match-set $IPSET_NAME_V4"; then
  # we may also have assumed that INPUT rule n°1 is about packets statistics (traffic monitoring)
  if [[ ${FORCE:-no} != yes ]]; then
    echo >&2 "Error: iptables does not have the needed ipset <CHAIN> rule, add it for example by using:"
    echo >&2 "# iptables -I INPUT ${IPTABLES_IPSET_RULE_NUMBER:-1} -m set --match-set $IPSET_NAME_V4 src -j DROP"
    echo >&2 "# iptables -I FORWARD ${IPTABLES_IPSET_RULE_NUMBER:-1} -m set --match-set $IPSET_NAME_V4 src -j DROP"
    exit 1
  fi
fi

# create the iptables binding if needed (or abort if does not exists and FORCE=no)
if ! ip6tables -nvL | command grep -q "match-set $IPSET_NAME_V6"; then
  # we may also have assumed that INPUT rule n°1 is about packets statistics (traffic monitoring)
  if [[ ${FORCE:-no} != yes ]]; then
    echo >&2 "Error: iptables does not have the needed ipset <CHAIN> rule, add it for example by using:"
    echo >&2 "# ip6tables -I INPUT ${IPTABLES_IPSET_RULE_NUMBER:-1} -m set --match-set $IPSET_NAME_V6 src -j DROP"
    echo >&2 "# ip6tables -I FORWARD ${IPTABLES_IPSET_RULE_NUMBER:-1} -m set --match-set $IPSET_NAME_V6 src -j DROP"
    exit 1
  fi
fi

IP_BLACKLIST_TMP=$(mktemp)
[[ ${VERBOSE:-yes} == yes ]] && echo -ne "\nIPv4: "
for url in "${BLACKLISTS[@]}"
do
  IP_TMP=$(mktemp)
  (( HTTP_RC=$(curl -L -A "blacklist-update/script/github" --connect-timeout 10 --max-time 10 -o "$IP_TMP" -s -w "%{http_code}" "$url") ))
  if (( HTTP_RC == 200 || HTTP_RC == 302 || HTTP_RC == 0 )); then # "0" because file:/// returns 000
    command grep -Po "^${IPV4_REGEX}" "$IP_TMP" | sed -r 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)$/\1.\2.\3.\4/' >> "$IP_BLACKLIST_TMP"
    [[ ${VERBOSE:-yes} == yes ]] && echo -n "."
  elif (( HTTP_RC == 503 )); then
    echo -e "\\nUnavailable (${HTTP_RC}): $url"
  else
    echo >&2 -e "\\nWarning: curl returned HTTP response code $HTTP_RC for URL $url"
  fi
  rm -f "$IP_TMP"
done

IP6_BLACKLIST_TMP=$(mktemp)
[[ ${VERBOSE:-yes} == yes ]] && echo -ne "\nIPv6: "
for url in "${BLACKLISTS6[@]}"
do
  IP_TMP=$(mktemp)
  (( HTTP_RC=$(curl -L -A "blacklist-update/script/github" --connect-timeout 10 --max-time 10 -o "$IP_TMP" -s -w "%{http_code}" "$url") ))
  if (( HTTP_RC == 200 || HTTP_RC == 302 || HTTP_RC == 0 )); then # "0" because file:/// returns 000
    command grep -Po "^${IPV6_REGEX}" "$IP_TMP" >> "$IP6_BLACKLIST_TMP"
    [[ ${VERBOSE:-yes} == yes ]] && echo -n "."
  elif (( HTTP_RC == 503 )); then
    echo -e "\\nUnavailable (${HTTP_RC}): $url"
  else
    echo >&2 -e "\\nWarning: curl returned HTTP response code $HTTP_RC for URL $url"
  fi
  rm -f "$IP_TMP"
done

# sort -nu does not work as expected
sed -r -e '/^(0\.0\.0\.0|10\.|127\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|22[4-9]\.|23[0-9]\.)/d' "$IP_BLACKLIST_TMP" | sort -V | sort -mu >| "$IP_BLACKLIST"
sed -r -e '/^([0:]+\/0|fe80:)/Id' "$IP6_BLACKLIST_TMP" | sort -d | sort -mu >| "$IP6_BLACKLIST"
if [[ ${DO_OPTIMIZE_CIDR} == yes ]]; then
  cidr-merger -o "$IP_BLACKLIST_TMP" -o "$IP6_BLACKLIST_TMP" "$IP_BLACKLIST" "$IP6_BLACKLIST"
  if [[ ${VERBOSE:-no} == yes ]]; then
    echo ""
    echo "IPv4 Addresses before CIDR optimization: $(wc -l "$IP_BLACKLIST" | cut -d' ' -f1)"
    echo "IPv4 Addresses after CIDR optimization:  $(wc -l "$IP_BLACKLIST_TMP" | cut -d' ' -f1)"
    echo "IPv6 Addresses before CIDR optimization: $(wc -l "$IP6_BLACKLIST" | cut -d' ' -f1)"
    echo "IPv6 Addresses after CIDR optimization:  $(wc -l "$IP6_BLACKLIST_TMP" | cut -d' ' -f1)"
  fi
  mv -f "$IP_BLACKLIST_TMP" "$IP_BLACKLIST"
  mv -f "$IP6_BLACKLIST_TMP" "$IP6_BLACKLIST"
fi

# family = inet for IPv4 only
cat >| "$IP_BLACKLIST_RESTORE" <<EOF
create "${IPSET_NAME_V4}${IPSET_TMP_NAME_POSTFIX}" -exist hash:net family inet hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}
create $IPSET_NAME_V4 -exist hash:net family inet hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}
EOF

# family = inet6 for IPv6 only
cat >| "$IP6_BLACKLIST_RESTORE" <<EOF
create "${IPSET_NAME_V6}${IPSET_TMP_NAME_POSTFIX}" -exist hash:net family inet6 hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}
create $IPSET_NAME_V6 -exist hash:net family inet6 hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}
EOF

cat >> "$IP_BLACKLIST_RESTORE" <<EOF
swap $IPSET_NAME_V4 ${IPSET_NAME_V4}${IPSET_TMP_NAME_POSTFIX}
destroy ${IPSET_NAME_V4}${IPSET_TMP_NAME_POSTFIX}
EOF

cat >> "$IP6_BLACKLIST_RESTORE" <<EOF
swap $IPSET_NAME_V6 ${IPSET_NAME_V6}${IPSET_TMP_NAME_POSTFIX}
destroy ${IPSET_NAME_V6}${IPSET_TMP_NAME_POSTFIX}
EOF

ipset -file "$IP_BLACKLIST_RESTORE" restore
ipset -file "$IP6_BLACKLIST_RESTORE" restore

if [[ ${VERBOSE:-no} == yes ]]; then
  echo
  echo "IPv4 Blacklisted addresses found: $(wc -l "$IP_BLACKLIST" | cut -d' ' -f1)"
  echo "IPv6 Blacklisted addresses found: $(wc -l "$IP6_BLACKLIST" | cut -d' ' -f1)"
fi

# Save ipset so ipset-persistent can load it again
ipset save > /etc/iptables/ipsets
