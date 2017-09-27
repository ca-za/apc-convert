# SOPHOS APC to OVPN and OVPN to APC convert tool
a little script which converts sophos apc site-to-site vpn tunnel config files to OpenVPN ovpn and vice versa.

**usage sample:**

`apc-convert.py ovpn2apc --username USER --password PASS input.ovpn ouput.apc`

`apc-convert.py apc2ovpn input.apc output.ovpn`

Beside the ssl key, certificates and cipher, **Sophos XG Firewall OS requires username, password, remote-cert-tls and auth SHA256**
