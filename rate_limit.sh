#!/bin/bash
# OBJECTIVE: rate limit the cLDAP inboud traffic to evade cLDAP DDoS amplification attack
# add this to your initialization iptables script

#iptables -F
#iptables -X

iptables -N CLDAP_RATE_LIMIT
	iptables -A CLDAP_RATE_LIMIT -m hashlimit --hashlimit-above 5/minute --hashlimit-mode srcip --hashlimit-name cldap_rate_limit -j DROP
	iptables -A CLDAP_RATE_LIMIT -m hashlimit --hashlimit-above 10/hour --hashlimit-mode srcip --hashlimit-name cldap_rate_limit -j DROP
	iptables -A CLDAP_RATE_LIMIT -j ACCEPT
# optionally jump to your custom LOG_DROP or LOG_ACCEPT chains

# cLDAP honeypot
iptables -I INPUT -p udp --dport 389 -j CLDAP_RATE_LIMIT
