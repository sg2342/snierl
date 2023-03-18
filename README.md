snierl
=====

SNI proxy with builtin letsencrypt ACME-v2 client

Build
-----

    $ rebar3 compile

Test
----


    $ rebar3 as test do dialyzer,xref,fmt,lint

Use
-----

with the following snierl application environment

~~~
[
    {snierl,
        %% listen on https port (default is 5555)
        [
            {listen, [{443, [inet]}, {443, [inet6]}]},
            %% letsencrypt production url (default is staging)
            {acme_directory_url, <<"https://acme-v02.api.letsencrypt.org/directory">>},
            %% letsencrypt account file location
            {acme_account_file, "/var/db/snierl/account.json"},
            %% storage for letsencrypt signed certs (and keys)
            {acme_certs_dets, "/var/db/snierl/acme_certs.dets"},
            %% SNI handshake options and destinations
            {sni_hosts, [
                {"www.example.com", #{
                    hs_opts => acme,
                    dst => {"localhost", 8080}
                }},
                {"example.com", #{
                    hs_opts => acme,
                    dst => {snierl_proxy, #{dst => {"localhost", 8080}}}
                }},
                {"special.example.com", #{
                    hs_opts => acme,
                    hs_extra => [
                        {verify, verify_peer},
                        {cacertfile, "/var/db/snierl/special_client_ca.crt"},
                        {vail_if_no_peer_cert, false}
                    ],
                    dst => {"localhost", 8080},
                    ext => #{
                        oid => {1, 3, 6, 1, 4, 1, 32473, 23, 42},
                        dsts => [
                            {<<4, 3, "foo">>, {"foo.special", 80}},
                            {<<4, 3, "bar">>, bar_proxy_mod},
                            {<<4, 6, "foobar">>, {foobar_proxy, #{a => 1}}}
                        ]
                    }
                }},
                {"private.example.com", #{
                    hs_opts => [
                        {certfile, "/var/db/snierl/private.crt"},
                        {keyfile, "/var/db/snierl/private.key"}
                    ],
                    dst => {
                        snierl_proxy, {{127, 0, 0, 1}, 7474}
                    }
                }}
            ]}
        ]}
].
~~~

acme interaction:

the snierl application will load the letsencrypt account from
/var/db/acme_account.json or - if the file does not exists -:
create a new account and store it.

on startup an then every hour:

for all entries in sni_hosts that have hs_opts set to acme:
("www.example.com", "example.com" and "special.example.com")

if a certificate does not exist in the dets, or the certificates expiry date is
less than 7 days in the future, snierl will request a certificate from
letsencrypt (using the tls-alpn-01 challenge) and store it in the dets file.

entries in dets that do not have a matching entry in the sni_hosts application
environment are removed from dets.

client connections:

to "www.example.com" will see a letsencrypt signed server certificate,
connection content is proxied to a tcp service on localhost port 8080.

to "example.com" will see a letsencrypt signed server certificate,
connection content is also proxied to a tcp service on localhost port 8080
with explicit configuration of snierl_proxy as proxy module.

to "private.example.com" will see the certificate from
"/var/db/snierl/private.crt", connection content is proxied to a tcp service
on 127.0.0.1 port 7474.

to "special.example.com" will see a letsencrypt signed certificate and a
client certificate request in the server tls hello message.
if no valid client certificate is sent, the connection will be proxied to
a tcp service on localhost 8080.

If a client certificate signed by a CA in "/var/db/snierl/special_client_ca.crt"
(and also any CA in the cert chain obtained from letsencrypt...) and
has the an non critical extension with extension OID 1.3.4.1.4.1.32473.23.42
then the connection content is proxied based on extension value.

for <<4, 3, "foo">>  it is proxied to a tcp service on host foo.special port 80

for <<4,3, "bar">> is proxied via the module bar_proxy_mod

for <<4,6, "foobar">> it is proxied via the module foobar_proxy that has
its proxy map set to #{a => 1}.
