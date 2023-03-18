-module(snierl_crts).

-export([alpn/3, csr/2, of_pem/2, extension/2]).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

-spec extension(tuple(), binary()) -> binary() | false.
extension(OID, DER) ->
    OtpC = public_key:pkix_decode_cert(DER, otp),
    TBS = OtpC#'OTPCertificate'.tbsCertificate,
    Extensions = TBS#'OTPTBSCertificate'.extensions,
    extension1(lists:keyfind(OID, 2, Extensions)).

extension1({'Extension', _OID, false, Value}) -> Value;
extension1(false) -> false.

-spec of_pem(PemBin :: binary(), Host :: string()) ->
    {Expires :: integer(), Cert :: binary(), CaCerts :: [binary()]}.
of_pem(PemBin, Host) ->
    {[Cert], CaCerts} =
        lists:splitwith(
            fun(C) -> public_key:pkix_verify_hostname(C, [{dns_id, Host}]) end,
            [C || {'Certificate', C, _} <- public_key:pem_decode(PemBin)]
        ),
    OtpCert = public_key:pkix_decode_cert(Cert, otp),
    TBSCert = OtpCert#'OTPCertificate'.tbsCertificate,
    {'Validity', _, NotAfterStr} = TBSCert#'OTPTBSCertificate'.validity,
    Expires = pubkey_cert:time_str_2_gregorian_sec(NotAfterStr),
    {Expires, Cert, CaCerts}.

-define(ALPN_EXT_ID, {1, 3, 6, 1, 5, 5, 7, 1, 31}).

-spec alpn(Key :: #'RSAPrivateKey'{}, Host :: string(), KeyAuth :: binary()) ->
    DERCert :: binary().
alpn(Key, Host, KeyAuth) ->
    Subject =
        {rdnSequence, [
            [
                #'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = {printableString, Host}
                }
            ]
        ]},
    {Y, M, D} = date(),
    [NotBefore, NotAfter] =
        [
            lists:flatten(io_lib:format("~w~2..0w~2..0w000001Z", V))
         || V <- [[Y - 1, M, D], [Y + 1, M, D]]
        ],
    TBS = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = 15,
        signature = #'SignatureAlgorithm'{
            algorithm = ?'sha256WithRSAEncryption',
            parameters = 'NULL'
        },
        issuer = Subject,
        subject = Subject,
        validity = #'Validity'{
            notBefore = {generalTime, NotBefore},
            notAfter = {generalTime, NotAfter}
        },
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
            algorithm = #'PublicKeyAlgorithm'{
                algorithm = ?rsaEncryption,
                parameters = 'NULL'
            },
            subjectPublicKey = #'RSAPublicKey'{
                modulus = Key#'RSAPrivateKey'.modulus,
                publicExponent = Key#'RSAPrivateKey'.publicExponent
            }
        },
        extensions = [
            #'Extension'{
                extnID = ?ALPN_EXT_ID,
                critical = true,
                extnValue = <<4, 32, KeyAuth/binary>>
            },
            #'Extension'{
                extnID = ?'id-ce-subjectAltName',
                critical = false,
                extnValue = [{dNSName, Host}]
            }
        ]
    },
    public_key:pkix_sign(TBS, Key).

-spec csr(Key :: #'RSAPrivateKey'{}, Host :: string()) ->
    CSR :: binary().
csr(Key, Host) ->
    A = #'AttributePKCS-10'{
        type = ?'pkcs-9-at-extensionRequest',
        values =
            [
                {asn1_OPENTYPE,
                    public_key:der_encode(
                        'ExtensionRequest',
                        [
                            #'Extension'{
                                extnID = ?'id-ce-subjectAltName',
                                critical = false,
                                extnValue =
                                    public_key:der_encode(
                                        'SubjectAltName',
                                        [{dNSName, Host}]
                                    )
                            }
                        ]
                    )}
            ]
    },
    CsrI = #'CertificationRequestInfo'{
        version = v1,
        subject = {rdnSequence, []},
        subjectPKInfo = #'CertificationRequestInfo_subjectPKInfo'{
            subjectPublicKey =
                public_key:der_encode(
                    'RSAPublicKey', #'RSAPublicKey'{
                        modulus = Key#'RSAPrivateKey'.modulus,
                        publicExponent = Key#'RSAPrivateKey'.publicExponent
                    }
                ),
            algorithm = #'CertificationRequestInfo_subjectPKInfo_algorithm'{
                algorithm = ?rsaEncryption,
                parameters = {asn1_OPENTYPE, <<5, 0>>}
            }
        },
        attributes = [A]
    },
    Csr = #'CertificationRequest'{
        certificationRequestInfo = CsrI,
        signatureAlgorithm = #'CertificationRequest_signatureAlgorithm'{
            algorithm = ?'sha256WithRSAEncryption'
        },
        signature =
            public_key:sign(
                public_key:der_encode(
                    'CertificationRequestInfo',
                    CsrI
                ),
                sha256,
                Key
            )
    },
    public_key:der_encode('CertificationRequest', Csr).
