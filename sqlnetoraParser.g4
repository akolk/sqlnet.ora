parser grammar sqlnetoraParser;

options {tokenVocab=sqlnetoraLexer;}

// ----------------------------------------------------------------
// Parser rules are lower case, or at least, an initial lower case.
// ----------------------------------------------------------------

//-----------------------------------------------------------------
// Top level rule. Start here with a complete tnsnames.ora file.
//-----------------------------------------------------------------
sqlnetora         : (sqlnet_entry | ifile )* ;

sqlnet_entry      : s_BEQUEATH_DETACH
                  | s_DEFAULT_SDU_SIZE
                  | s_DISABLE_OOB
                  | s_NAMES.DCE.PREFIX
                  | s_NAMES.DEFAULT_DOMAIN
                  | s NAMES.DIRECTORY_PATH
                  | s_NAMES.LDAP_AUTHENTICATE_BIND
                  | s_NAMES.LDAP_PERSISTENT_SESSION
                  | s_NAMES.NIS.META_MAP
                  | s_RECV_BUF_SIZE
                  | s_SDP.PF_INET_SDP
                  | s_SEC_USER_AUDIT_ACTION_BANNER
                  | s_SEC_USER_UNAUTHORIZED_ACCESS_BANNER
                 | s_SEND_BUF_SIZE
                 | s_SQLNET.ALLOWED_LOGON_VERSION
                 | s_SQLNET.AUTHENTICATION_KERBEROS5_SERVICE
                 | s_SQLNET.AUTHENTICATION_SERVICES
                 | s_SQLNET.CLIENT_REGISTRATION
                 | s_SQLNET.CRYPTO_CHECKSUM_CLIENT
                 | s_SQLNET.CRYPTO_CHECKSUM_SERVER
                 | s_SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT
                 | s_SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER
                 | s_SQLNET.CRYPTO_SEED
                 | s_SQLNET.ENCRYPTION_CLIENT
                 | s_SQLNET.ENCRYPTION_SERVER
                 | s_SQLNET.ENCRYPTION_TYPES_CLIENT
                 | s_SQLNET.ENCRYPTION_TYPES_SERVER
                 | s_SQLNET.EXPIRE_TIME
                 | s_SQLNET.INBOUND_CONNECT_TIMEOUT
                 | s_SQLNET.KERBEROS5_CC_NAME
                 | s_SQLNET.KERBEROS5_CLOCKSKEW
                 | s_SQLNET.KERBEROS5_CONF
                 | s_SQLNET.KERBEROS5_KEYTAB
                 | s_SQLNET.KERBEROS5_REALMS
                 | s_SQLNET.OUTBOUND_CONNECT_TIMEOUT
                 | s_SQLNET.RADIUS_ALTERNATE
                 | s_SQLNET.RADIUS_ALTERNATE_PORT
                 | s_SQLNET.RADIUS_ALTERNATE_RETRIES
                 | s_SQLNET.RADIUS_AUTHENTICATION
                 | s_SQLNET.RADIUS_AUTHENTICATION_INTERFACE
                 | s_SQLNET.RADIUS_AUTHENTICATION_PORT
                 | s_SQLNET.RADIUS_AUTHENTICATION_RETRIES
                 | s_SQLNET.RADIUS_AUTHENTICATION_TIMEOUT
                 | s_SQLNET.RADIUS_CHALLENGE_RESPONSE
                 | s_SQLNET.RADIUS_SECRET
                 | s_SQLNET.RADIUS_SEND_ACCOUNTING
                 | s_SQLNET.RECV_TIMEOUT
                 | s_SQLNET.SEND_TIMEOUT
                 | s_SSL_CERT_REVOCATION
                 | s_SSL_CERT_FILE
                 | s_SSL_CERT_PATH
                 | s_SSL_CIPHER_SUITES
                 | s_SSL_CLIENT_AUTHENTICATION
                 | s_SSL_SERVER_DN_MATCH
                 | s_SSL_VERSION
                 | s_TCP.CONNECT_TIMEOUT
                 | s_TCP.EXCLUDED_NODES
                 | s_TCP.INVITED_NODES
                 | s_TCP.VALIDNODE_CHECKING
                 | s_TCP.NODELAY
                 | s_TNSPING.TRACE_DIRECTORY
                 | s_TNSPING.TRACE_LEVEL
                 | s_USE_CMAN
                 | s_USE_DEDICATED_SERVER
                 | s_WALLET_LOCATION
                 | s_WALLET_OVERRIDE;
                 
s_default_sdu_size : DEFAULT_SDU_SIZE EQUAL INT;

s_tcp_connect_timeout : TCP_CONNECT_TIMEOUT EQUAL INT;

// NAMES.DIRECTORY_PATH= (LDAP, TNSNAMES, HOSTNAME)
s_names_directory_path : NAMES_DIRECTORY_PATH EQUAL L_PAREN names_option (COMMA names_option)* R_PAREN

: alias_list EQUAL (description_list | description) ;
d_parameter      : d_enable
                 | al_failover
                 | al_load_balance
                 | d_sdu
                 | d_recv_buf
                 | d_send_buf
                 | al_source_route
                 | d_service_type
                 | d_security
                 | d_conn_timeout
                 | d_retry_count
                 | d_tct

ifile            : IFILE I_EQUAL I_STRING ;
