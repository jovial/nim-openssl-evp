
{.deadCodeElim: on.}
when defined(windows): 
  const 
    cryptodll* = "libcrypto.dll"
elif defined(macosx): 
  const 
    cryptodll* = "libcrypto.dylib"
else: 
  const 
    cryptodll* = "libcrypto.so"

type    
  time_t {.importc: "time_t", header: "<sys/time.h>".} = int

type
  SslStruct {.final, pure.} = object
  SslPtr = ptr SslStruct
  ASN1_ITEM_st = SslPtr
  asn1_pctx_st = SslPtr
  bignum_ctx = SslPtr
  bn_blinding_st = SslPtr
  buf_mem_st = SslPtr
  evp_cipher_st = SslPtr
  evp_cipher_ctx_st = SslPtr
  env_md_st = SslPtr
  env_md_ctx_st = SslPtr
  evp_pkey_st = SslPtr
  evp_pkey_asn1_method_st = SslPtr
  evp_pkey_method_st = SslPtr
  evp_pkey_ctx_st = SslPtr
  dh_st = SslPtr
  dh_method = SslPtr
  dsa_st = SslPtr
  dsa_method = SslPtr
  rsa_st = SslPtr
  rsa_meth_st = SslPtr
  rand_meth_st = SslPtr
  ecdh_method = SslPtr
  ecdsa_method = SslPtr
  x509_st = SslPtr
  X509_crl_st = SslPtr
  x509_crl_method_st = SslPtr
  x509_revoked_st = SslPtr
  X509_name_st = SslPtr
  X509_pubkey_st = SslPtr
  x509_store_st = SslPtr
  x509_store_ctx_st = SslPtr
  pkcs8_priv_key_info_st = SslPtr
  conf_st = SslPtr
  store_st = SslPtr
  store_method_st = SslPtr
  ui_st = SslPtr
  ui_method_st = SslPtr
  engine_st = SslPtr
  ssl_st = SslPtr
  ssl_ctx_st = SslPtr
  X509_POLICY_NODE_st = SslPtr
  X509_POLICY_LEVEL_st = SslPtr
  X509_POLICY_TREE_st = SslPtr
  X509_POLICY_CACHE_st = SslPtr
  AUTHORITY_KEYID_st = SslPtr
  DIST_POINT_st = SslPtr
  ISSUING_DIST_POINT_st = SslPtr
  NAME_CONSTRAINTS_st = SslPtr
  ocsp_req_ctx_st = SslPtr
  ocsp_response_st = SslPtr
  ocsp_responder_id_st = SslPtr
  ASN1_TEMPLATE_st = SslPtr
  ASN1_TLC_st = SslPtr
  ASN1_VALUE_st = SslPtr
  v3_ext_ctx = SslPtr
  st_ERR_FNS = SSlPtr
  st_CRYPTO_EX_DATA_IMPL = SslPtr
  OBJ_NAME = SslPtr
  
  #CHECK THESE!
  hostent = SslPtr
  #END
  
  ASN1_INTEGER* = asn1_string_st
  ASN1_ENUMERATED* = asn1_string_st
  ASN1_BIT_STRING* = asn1_string_st
  ASN1_OCTET_STRING* = asn1_string_st
  ASN1_PRINTABLESTRING* = asn1_string_st
  ASN1_T61STRING* = asn1_string_st
  ASN1_IA5STRING* = asn1_string_st
  ASN1_GENERALSTRING* = asn1_string_st
  ASN1_UNIVERSALSTRING* = asn1_string_st
  ASN1_BMPSTRING* = asn1_string_st
  ASN1_UTCTIME* = asn1_string_st
  ASN1_TIME* = asn1_string_st
  ASN1_GENERALIZEDTIME* = asn1_string_st
  ASN1_VISIBLESTRING* = asn1_string_st
  ASN1_UTF8STRING* = asn1_string_st
  ASN1_STRING* = asn1_string_st
  ASN1_BOOLEAN* = cint
  ASN1_NULL* = cint
  ASN1_ITEM* = ASN1_ITEM_st
  ASN1_PCTX* = asn1_pctx_st
  BIGNUM* = bignum_st
  BN_CTX* = bignum_ctx
  BN_BLINDING* = bn_blinding_st
  BN_MONT_CTX* = bn_mont_ctx_st
  BN_RECP_CTX* = bn_recp_ctx_st
  BN_GENCB* = bn_gencb_st
  BUF_MEM* = buf_mem_st
  EVP_CIPHER* = evp_cipher_st
  EVP_CIPHER_CTX* = evp_cipher_ctx_st
  EVP_MD* = env_md_st
  EVP_MD_CTX* = env_md_ctx_st
  EVP_PKEY* = evp_pkey_st
  EVP_PKEY_ASN1_METHOD* = evp_pkey_asn1_method_st
  EVP_PKEY_METHOD* = evp_pkey_method_st
  EVP_PKEY_CTX* = evp_pkey_ctx_st
  DH* = dh_st
  DH_METHOD* = dh_method
  DSA* = dsa_st
  DSA_METHOD* = dsa_method
  RSA* = rsa_st
  RSA_METHOD* = rsa_meth_st
  RAND_METHOD* = rand_meth_st
  ECDH_METHOD* = ecdh_method
  ECDSA_METHOD* = ecdsa_method
  X509* = x509_st
  X509_ALGOR* = X509_algor_st
  X509_CRL* = X509_crl_st
  X509_CRL_METHOD* = x509_crl_method_st
  X509_REVOKED* = x509_revoked_st
  X509_NAME* = X509_name_st
  X509_PUBKEY* = X509_pubkey_st
  X509_STORE* = x509_store_st
  X509_STORE_CTX* = x509_store_ctx_st
  PKCS8_PRIV_KEY_INFO* = pkcs8_priv_key_info_st
  X509V3_CTX* = v3_ext_ctx
  CONF* = conf_st
  STORE* = store_st
  STORE_METHOD* = store_method_st
  UI* = ui_st
  UI_METHOD* = ui_method_st
  ERR_FNS* = st_ERR_FNS
  ENGINE* = engine_st
  SSL* = ssl_st
  SSL_CTX* = ssl_ctx_st
  X509_POLICY_NODE* = X509_POLICY_NODE_st
  X509_POLICY_LEVEL* = X509_POLICY_LEVEL_st
  X509_POLICY_TREE* = X509_POLICY_TREE_st
  X509_POLICY_CACHE* = X509_POLICY_CACHE_st
  AUTHORITY_KEYID* = AUTHORITY_KEYID_st
  DIST_POINT* = DIST_POINT_st
  ISSUING_DIST_POINT* = ISSUING_DIST_POINT_st
  NAME_CONSTRAINTS* = NAME_CONSTRAINTS_st
  CRYPTO_EX_DATA* = crypto_ex_data_st
  CRYPTO_EX_new* = proc (parent: pointer; pntr: pointer; ad: ptr CRYPTO_EX_DATA; 
                         idx: cint; argl: clong; argp: pointer): cint {.cdecl.}
  CRYPTO_EX_free* = proc (parent: pointer; pntr: pointer; ad: ptr CRYPTO_EX_DATA; 
                          idx: cint; argl: clong; argp: pointer) {.cdecl.}
  CRYPTO_EX_dup* = proc (to: ptr CRYPTO_EX_DATA; frm: ptr CRYPTO_EX_DATA; 
                         from_d: pointer; idx: cint; argl: clong; argp: pointer): cint {.
      cdecl.}
  OCSP_REQ_CTX* = ocsp_req_ctx_st
  OCSP_RESPONSE* = ocsp_response_st
  OCSP_RESPID* = ocsp_responder_id_st
  mStack* = object 
    num*: cint
    data*: cstringArray
    sorted*: cint
    num_alloc*: cint
    comp*: proc (a2: pointer; a3: pointer): cint {.cdecl.}
    
  
  OPENSSL_STRING* = cstring
  OPENSSL_CSTRING* = cstring
  stack_st_OPENSSL_STRING* = object 
    stack*: mStack

  OPENSSL_BLOCK* = pointer
  stack_st_OPENSSL_BLOCK* = object 
    stack*: mStack

  OPENSSL_ITEM* = object 
    code*: cint
    value*: pointer
    value_size*: csize
    value_length*: ptr csize

  BIO_dummy* = bio_st
  crypto_ex_data_st* = object 
    sk*: ptr stack_st_void
    dummy*: cint

  stack_st_void* = object 
    stack*: mStack

  CRYPTO_EX_DATA_FUNCS* = object 
    argl*: clong
    argp*: pointer
    new_func*: ptr CRYPTO_EX_new
    free_func*: ptr CRYPTO_EX_free
    dup_func*: ptr CRYPTO_EX_dup

  stack_st_CRYPTO_EX_DATA_FUNCS* = object 
    stack*: mStack

  CRYPTO_THREADID_OBJ* = object 
    pntr*: pointer
    val*: culong
 
  bio_info_cb* = proc (a2: ptr bio_st; a3: cint; a4: cstring; a5: cint; 
                       a6: clong; a7: clong) {.cdecl.}
  BIO_METHOD* = object 
    typ*: cint
    name*: cstring
    bwrite*: proc (a2: ptr BIO; a3: cstring; a4: cint): cint {.cdecl.}
    bread*: proc (a2: ptr BIO; a3: cstring; a4: cint): cint {.cdecl.}
    bputs*: proc (a2: ptr BIO; a3: cstring): cint {.cdecl.}
    bgets*: proc (a2: ptr BIO; a3: cstring; a4: cint): cint {.cdecl.}
    ctrl*: proc (a2: ptr BIO; a3: cint; a4: clong; a5: pointer): clong {.cdecl.}
    create*: proc (a2: ptr BIO): cint {.cdecl.}
    destroy*: proc (a2: ptr BIO): cint {.cdecl.}
    callback_ctrl*: proc (a2: ptr BIO; a3: cint; a4: ptr bio_info_cb): clong {.
        cdecl.}

  bio_st* = object 
    methd*: ptr BIO_METHOD
    callback*: proc (a2: ptr bio_st; a3: cint; a4: cstring; a5: cint; a6: clong; 
                     a7: clong): clong {.cdecl.}
    cb_arg*: cstring
    init*: cint
    shutdown*: cint
    flags*: cint
    retry_reason*: cint
    num*: cint
    pntr*: pointer
    next_bio*: ptr bio_st
    prev_bio*: ptr bio_st
    references*: cint
    num_read*: culong
    num_write*: culong
    ex_data*: CRYPTO_EX_DATA

  stack_st_BIO* = object 
    stack*: mStack
  
  BIO* = bio_st  

  BIO_F_BUFFER_CTX* = object 
    ibuf_size*: cint
    obuf_size*: cint
    ibuf*: cstring
    ibuf_len*: cint
    ibuf_off*: cint
    obuf*: cstring
    obuf_len*: cint
    obuf_off*: cint

  asn1_ps_func* = proc (b: ptr BIO; pbuf: ptr ptr cuchar; plen: ptr cint; 
                        parg: pointer): cint {.cdecl.}
                        
  CRYPTO_EX_DATA_IMPL* = st_CRYPTO_EX_DATA_IMPL
  
  CRYPTO_MEM_LEAK_CB* = proc (a2: culong; a3: cstring; a4: cint; a5: cint; 
                              a6: pointer): pointer {.cdecl.}
                              
  bignum_st* = object 
    d*: ptr culong
    top*: cint
    dmax*: cint
    neg*: cint
    flags*: cint

  bn_mont_ctx_st* = object 
    ri*: cint
    RR*: BIGNUM
    N*: BIGNUM
    Ni*: BIGNUM
    n0*: array[2, culong]
    flags*: cint

  bn_recp_ctx_st* = object 
    N*: BIGNUM
    Nr*: BIGNUM
    num_bits*: cint
    shift*: cint
    flags*: cint

  INNER_C_UNION_1020486196504891075* = object  {.union.}
    cb_1*: proc (a2: cint; a3: cint; a4: pointer) {.cdecl.}
    cb_2*: proc (a2: cint; a3: cint; a4: ptr BN_GENCB): cint {.cdecl.}

  bn_gencb_st* = object 
    ver*: cuint
    arg*: pointer
    cb*: INNER_C_UNION_1020486196504891075 
    
  X509_algor_st* = object 
  
  stack_st_X509_ALGOR* = object 
    stack*: mStack

  ASN1_CTX* = object 
    p*: ptr cuchar
    eos*: cint
    error*: cint
    inf*: cint
    tag*: cint
    xclass*: cint
    slen*: clong
    max*: ptr cuchar
    q*: ptr cuchar
    pp*: ptr ptr cuchar
    line*: cint

  ASN1_const_CTX* = object 
    p*: ptr cuchar
    eos*: cint
    error*: cint
    inf*: cint
    tag*: cint
    xclass*: cint
    slen*: clong
    max*: ptr cuchar
    q*: ptr cuchar
    pp*: ptr ptr cuchar
    line*: cint

  ASN1_OBJECT* = object 
    sn*: cstring
    ln*: cstring
    nid*: cint
    length*: cint
    data*: ptr cuchar
    flags*: cint

  asn1_string_st* = object 
    length*: cint
    typ*: cint
    data*: ptr cuchar
    flags*: clong

  ASN1_ENCODING* = object 
    enc*: ptr cuchar
    len*: clong
    modified*: cint

  ASN1_STRING_TABLE* = object 
    nid*: cint
    minsize*: clong
    maxsize*: clong
    mask*: culong
    flags*: culong

  stack_st_ASN1_STRING_TABLE* = object 
    stack*: mStack

  ASN1_TEMPLATE* = ASN1_TEMPLATE_st
  ASN1_TLC* = ASN1_TLC_st
  ASN1_VALUE* = ASN1_VALUE_st
  d2i_of_void* = proc (a2: ptr pointer; a3: ptr ptr cuchar; a4: clong): pointer {.
      cdecl.}
  i2d_of_void* = proc (a2: pointer; a3: ptr ptr cuchar): cint {.cdecl.}
  ASN1_ITEM_EXP* = ASN1_ITEM
  stack_st_ASN1_INTEGER* = object 
    stack*: mStack

  stack_st_ASN1_GENERALSTRING* = object 
    stack*: mStack

  INNER_C_UNION_15884546358380581324* = object  {.union.}
    pntr*: cstring
    boolean*: ASN1_BOOLEAN
    asn1_string*: ptr ASN1_STRING
    obj*: ptr ASN1_OBJECT
    integer*: ptr ASN1_INTEGER
    enumerated*: ptr ASN1_ENUMERATED
    bit_string*: ptr ASN1_BIT_STRING
    octet_string*: ptr ASN1_OCTET_STRING
    printablestring*: ptr ASN1_PRINTABLESTRING
    t61string*: ptr ASN1_T61STRING
    ia5string*: ptr ASN1_IA5STRING
    generalstring*: ptr ASN1_GENERALSTRING
    bmpstring*: ptr ASN1_BMPSTRING
    universalstring*: ptr ASN1_UNIVERSALSTRING
    utctime*: ptr ASN1_UTCTIME
    generalizedtime*: ptr ASN1_GENERALIZEDTIME
    visiblestring*: ptr ASN1_VISIBLESTRING
    utf8string*: ptr ASN1_UTF8STRING
    set*: ptr ASN1_STRING
    sequence*: ptr ASN1_STRING
    asn1_value*: ptr ASN1_VALUE

  ASN1_TYPE* = object 
    typ*: cint
    value*: INNER_C_UNION_15884546358380581324

  stack_st_ASN1_TYPE* = object 
    stack*: mStack

  ASN1_SEQUENCE_ANY* = stack_st_ASN1_TYPE 
  
  NETSCAPE_X509* = object 
    header*: ptr ASN1_OCTET_STRING
    cert*: ptr X509

  BIT_STRING_BITNAME* = object 
    bitnum*: cint
    lname*: cstring
    sname*: cstring
     
  stack_st_ASN1_OBJECT* = object 
    stack*: mStack
                        
#  CRYPTO_dynlock* = object 
#    references*: cint
#    data*: ptr CRYPTO_dynlock_value
    
proc sk_num*(a2: ptr mStack): cint {.cdecl, importc: "sk_num", dynlib: cryptodll.}
proc sk_value*(a2: ptr mStack; a3: cint): pointer {.cdecl, importc: "sk_value", 
    dynlib: cryptodll.}
proc sk_set*(a2: ptr mStack; a3: cint; a4: pointer): pointer {.cdecl, 
    importc: "sk_set", dynlib: cryptodll.}
proc sk_new*(cmp: proc (a2: pointer; a3: pointer): cint {.cdecl.}): ptr mStack {.
    cdecl, importc: "sk_new", dynlib: cryptodll.}
proc sk_new_null*(): ptr mStack {.cdecl, importc: "sk_new_null", 
                                  dynlib: cryptodll.}
proc sk_free*(a2: ptr mStack) {.cdecl, importc: "sk_free", dynlib: cryptodll.}
proc sk_pop_free*(st: ptr mStack; func: proc (a2: pointer) {.cdecl.}) {.cdecl, 
    importc: "sk_pop_free", dynlib: cryptodll.}
proc sk_insert*(sk: ptr mStack; data: pointer; where: cint): cint {.cdecl, 
    importc: "sk_insert", dynlib: cryptodll.}
proc sk_delete*(st: ptr mStack; loc: cint): pointer {.cdecl, 
    importc: "sk_delete", dynlib: cryptodll.}
proc sk_delete_ptr*(st: ptr mStack; p: pointer): pointer {.cdecl, 
    importc: "sk_delete_ptr", dynlib: cryptodll.}
proc sk_find*(st: ptr mStack; data: pointer): cint {.cdecl, importc: "sk_find", 
    dynlib: cryptodll.}
proc sk_find_ex*(st: ptr mStack; data: pointer): cint {.cdecl, 
    importc: "sk_find_ex", dynlib: cryptodll.}
proc sk_push*(st: ptr mStack; data: pointer): cint {.cdecl, importc: "sk_push", 
    dynlib: cryptodll.}
proc sk_unshift*(st: ptr mStack; data: pointer): cint {.cdecl, 
    importc: "sk_unshift", dynlib: cryptodll.}
proc sk_shift*(st: ptr mStack): pointer {.cdecl, importc: "sk_shift", 
    dynlib: cryptodll.}
proc sk_pop*(st: ptr mStack): pointer {.cdecl, importc: "sk_pop", 
                                        dynlib: cryptodll.}
proc sk_zero*(st: ptr mStack) {.cdecl, importc: "sk_zero", dynlib: cryptodll.}
#int (*sk_set_cmp_func(mStack *sk, int (*c)(const void *, const void *)))
# (const void *, const void *);

proc sk_dup*(st: ptr mStack): ptr mStack {.cdecl, importc: "sk_dup", 
    dynlib: cryptodll.}
proc sk_sort*(st: ptr mStack) {.cdecl, importc: "sk_sort", dynlib: cryptodll.}
proc sk_is_sorted*(st: ptr mStack): cint {.cdecl, importc: "sk_is_sorted", 
    dynlib: cryptodll.}

proc CRYPTO_mem_ctrl*(mode: cint): cint {.cdecl, importc: "CRYPTO_mem_ctrl", 
    dynlib: cryptodll.}
proc CRYPTO_is_mem_check_on*(): cint {.cdecl, importc: "CRYPTO_is_mem_check_on", 
                                       dynlib: cryptodll.}
proc SSLeay_version*(typ: cint): cstring {.cdecl, importc: "SSLeay_version", 
    dynlib: cryptodll.}
proc SSLeay*(): culong {.cdecl, importc: "SSLeay", dynlib: cryptodll.}
proc OPENSSL_issetugid*(): cint {.cdecl, importc: "OPENSSL_issetugid", 
                                  dynlib: cryptodll.}

proc CRYPTO_get_ex_data_implementation*(): ptr CRYPTO_EX_DATA_IMPL {.cdecl, 
    importc: "CRYPTO_get_ex_data_implementation", dynlib: cryptodll.}
proc CRYPTO_set_ex_data_implementation*(i: ptr CRYPTO_EX_DATA_IMPL): cint {.
    cdecl, importc: "CRYPTO_set_ex_data_implementation", dynlib: cryptodll.}
proc CRYPTO_ex_data_new_class*(): cint {.cdecl, 
    importc: "CRYPTO_ex_data_new_class", dynlib: cryptodll.}
proc CRYPTO_get_ex_new_index*(class_index: cint; argl: clong; argp: pointer; 
                              new_func: ptr CRYPTO_EX_new; 
                              dup_func: ptr CRYPTO_EX_dup; 
                              free_func: ptr CRYPTO_EX_free): cint {.cdecl, 
    importc: "CRYPTO_get_ex_new_index", dynlib: cryptodll.}
proc CRYPTO_new_ex_data*(class_index: cint; obj: pointer; ad: ptr CRYPTO_EX_DATA): cint {.
    cdecl, importc: "CRYPTO_new_ex_data", dynlib: cryptodll.}
proc CRYPTO_dup_ex_data*(class_index: cint; to: ptr CRYPTO_EX_DATA; 
                         frm: ptr CRYPTO_EX_DATA): cint {.cdecl, 
    importc: "CRYPTO_dup_ex_data", dynlib: cryptodll.}
proc CRYPTO_free_ex_data*(class_index: cint; obj: pointer; 
                          ad: ptr CRYPTO_EX_DATA) {.cdecl, 
    importc: "CRYPTO_free_ex_data", dynlib: cryptodll.}
proc CRYPTO_set_ex_data*(ad: ptr CRYPTO_EX_DATA; idx: cint; val: pointer): cint {.
    cdecl, importc: "CRYPTO_set_ex_data", dynlib: cryptodll.}
proc CRYPTO_get_ex_data*(ad: ptr CRYPTO_EX_DATA; idx: cint): pointer {.cdecl, 
    importc: "CRYPTO_get_ex_data", dynlib: cryptodll.}
proc CRYPTO_cleanup_all_ex_data*() {.cdecl, 
                                     importc: "CRYPTO_cleanup_all_ex_data", 
                                     dynlib: cryptodll.}
proc CRYPTO_get_new_lockid*(name: cstring): cint {.cdecl, 
    importc: "CRYPTO_get_new_lockid", dynlib: cryptodll.}
proc CRYPTO_num_locks*(): cint {.cdecl, importc: "CRYPTO_num_locks", 
                                 dynlib: cryptodll.}
proc CRYPTO_lock*(mode: cint; typ: cint; file: cstring; line: cint) {.cdecl, 
    importc: "CRYPTO_lock", dynlib: cryptodll.}
#void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
#           const char *file,int line));
#void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
#  int line);
#void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type,
#           const char *file, int line));
#int (*CRYPTO_get_add_lock_callback(void))(int *num,int mount,int type,
#       const char *file,int line);


proc CRYPTO_THREADID_set_numeric*(id: ptr CRYPTO_THREADID_OBJ; val: culong) {.cdecl, 
    importc: "CRYPTO_THREADID_set_numeric", dynlib: cryptodll.}
proc CRYPTO_THREADID_set_pointer*(id: ptr CRYPTO_THREADID_OBJ; pntr: pointer) {.
    cdecl, importc: "CRYPTO_THREADID_set_pointer", dynlib: cryptodll.}
proc CRYPTO_THREADID_set_callback*(threadid_func: proc (a2: ptr CRYPTO_THREADID_OBJ) {.
    cdecl.}): cint {.cdecl, importc: "CRYPTO_THREADID_set_callback", 
                     dynlib: cryptodll.}
#void (*CRYPTO_THREADID_get_callback(void))(CRYPTO_THREADID *);

proc CRYPTO_THREADID_current*(id: ptr CRYPTO_THREADID_OBJ) {.cdecl, 
    importc: "CRYPTO_THREADID_current", dynlib: cryptodll.}
proc CRYPTO_THREADID_cmp*(a: ptr CRYPTO_THREADID_OBJ; b: ptr CRYPTO_THREADID_OBJ): cint {.
    cdecl, importc: "CRYPTO_THREADID_cmp", dynlib: cryptodll.}
proc CRYPTO_THREADID_cpy*(dest: ptr CRYPTO_THREADID_OBJ; src: ptr CRYPTO_THREADID_OBJ) {.
    cdecl, importc: "CRYPTO_THREADID_cpy", dynlib: cryptodll.}
proc CRYPTO_THREADID_hash*(id: ptr CRYPTO_THREADID_OBJ): culong {.cdecl, 
    importc: "CRYPTO_THREADID_hash", dynlib: cryptodll.}
proc CRYPTO_set_id_callback*(func: proc (): culong {.cdecl.}) {.cdecl, 
    importc: "CRYPTO_set_id_callback", dynlib: cryptodll.}
#unsigned long (*CRYPTO_get_id_callback(void))(void);

proc CRYPTO_thread_id*(): culong {.cdecl, importc: "CRYPTO_thread_id", 
                                   dynlib: cryptodll.}
proc CRYPTO_get_lock_name*(typ: cint): cstring {.cdecl, 
    importc: "CRYPTO_get_lock_name", dynlib: cryptodll.}
proc CRYPTO_add_lock*(pointer: ptr cint; amount: cint; typ: cint; 
                      file: cstring; line: cint): cint {.cdecl, 
    importc: "CRYPTO_add_lock", dynlib: cryptodll.}
proc CRYPTO_get_new_dynlockid*(): cint {.cdecl, 
    importc: "CRYPTO_get_new_dynlockid", dynlib: cryptodll.}
proc CRYPTO_destroy_dynlockid*(i: cint) {.cdecl, 
    importc: "CRYPTO_destroy_dynlockid", dynlib: cryptodll.}
# user has to define: ptr CRYPTO_dynlock_value for this I think
#proc CRYPTO_get_dynlock_value*(i: cint): ptr CRYPTO_dynlock_value {.cdecl, 
#    importc: "CRYPTO_get_dynlock_value", dynlib: cryptodll.}
#proc CRYPTO_set_dynlock_create_callback*(dyn_create_function: proc (
#    file: cstring; line: cint): ptr CRYPTO_dynlock_value {.cdecl.}) {.cdecl, 
#    importc: "CRYPTO_set_dynlock_create_callback", dynlib: cryptodll.}
#proc CRYPTO_set_dynlock_lock_callback*(dyn_lock_function: proc (mode: cint; 
#    l: ptr CRYPTO_dynlock_value; file: cstring; line: cint) {.cdecl.}) {.cdecl, 
#    importc: "CRYPTO_set_dynlock_lock_callback", dynlib: cryptodll.}
#proc CRYPTO_set_dynlock_destroy_callback*(dyn_destroy_function: proc (
#    l: ptr CRYPTO_dynlock_value; file: cstring; line: cint) {.cdecl.}) {.cdecl, 
#    importc: "CRYPTO_set_dynlock_destroy_callback", dynlib: cryptodll.}
#struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))(const char *file,int line);
#void (*CRYPTO_get_dynlock_lock_callback(void))(int mode, struct CRYPTO_dynlock_value *l, const char *file,int line);
#void (*CRYPTO_get_dynlock_destroy_callback(void))(struct CRYPTO_dynlock_value *l, const char *file,int line);

proc CRYPTO_set_mem_functions*(m: proc (a2: csize): pointer {.cdecl.}; r: proc (
    a2: pointer; a3: csize): pointer {.cdecl.}; f: proc (a2: pointer) {.cdecl.}): cint {.
    cdecl, importc: "CRYPTO_set_mem_functions", dynlib: cryptodll.}
proc CRYPTO_set_locked_mem_functions*(m: proc (a2: csize): pointer {.cdecl.}; 
                                      free_func: proc (a2: pointer) {.cdecl.}): cint {.
    cdecl, importc: "CRYPTO_set_locked_mem_functions", dynlib: cryptodll.}
proc CRYPTO_set_mem_ex_functions*(m: proc (a2: csize; a3: cstring; a4: cint): pointer {.
    cdecl.}; r: proc (a2: pointer; a3: csize; a4: cstring; a5: cint): pointer {.
    cdecl.}; f: proc (a2: pointer) {.cdecl.}): cint {.cdecl, 
    importc: "CRYPTO_set_mem_ex_functions", dynlib: cryptodll.}
proc CRYPTO_set_locked_mem_ex_functions*(
    m: proc (a2: csize; a3: cstring; a4: cint): pointer {.cdecl.}; 
    free_func: proc (a2: pointer) {.cdecl.}): cint {.cdecl, 
    importc: "CRYPTO_set_locked_mem_ex_functions", dynlib: cryptodll.}
proc CRYPTO_set_mem_debug_functions*(m: proc (a2: pointer; a3: cint; 
    a4: cstring; a5: cint; a6: cint) {.cdecl.}; r: proc (a2: pointer; 
    a3: pointer; a4: cint; a5: cstring; a6: cint; a7: cint) {.cdecl.}; 
                                     f: proc (a2: pointer; a3: cint) {.cdecl.}; 
                                     so: proc (a2: clong) {.cdecl.}; 
                                     go: proc (): clong {.cdecl.}): cint {.
    cdecl, importc: "CRYPTO_set_mem_debug_functions", dynlib: cryptodll.}
proc CRYPTO_get_mem_functions*(m: proc (a2: csize): pointer {.cdecl.}; r: proc (
    a2: pointer; a3: csize): pointer {.cdecl.}; f: proc (a2: pointer) {.cdecl.}) {.
    cdecl, importc: "CRYPTO_get_mem_functions", dynlib: cryptodll.}
proc CRYPTO_get_locked_mem_functions*(m: proc (a2: csize): pointer {.cdecl.}; 
                                      f: proc (a2: pointer) {.cdecl.}) {.cdecl, 
    importc: "CRYPTO_get_locked_mem_functions", dynlib: cryptodll.}
proc CRYPTO_get_mem_ex_functions*(m: proc (a2: csize; a3: cstring; a4: cint): pointer {.
    cdecl.}; r: proc (a2: pointer; a3: csize; a4: cstring; a5: cint): pointer {.
    cdecl.}; f: proc (a2: pointer) {.cdecl.}) {.cdecl, 
    importc: "CRYPTO_get_mem_ex_functions", dynlib: cryptodll.}
proc CRYPTO_get_locked_mem_ex_functions*(
    m: proc (a2: csize; a3: cstring; a4: cint): pointer {.cdecl.}; 
    f: proc (a2: pointer) {.cdecl.}) {.cdecl, importc: "CRYPTO_get_locked_mem_ex_functions", 
                                       dynlib: cryptodll.}
proc CRYPTO_get_mem_debug_functions*(m: proc (a2: pointer; a3: cint; 
    a4: cstring; a5: cint; a6: cint) {.cdecl.}; r: proc (a2: pointer; 
    a3: pointer; a4: cint; a5: cstring; a6: cint; a7: cint) {.cdecl.}; 
                                     f: proc (a2: pointer; a3: cint) {.cdecl.}; 
                                     so: proc (a2: clong) {.cdecl.}; 
                                     go: proc (): clong {.cdecl.}) {.cdecl, 
    importc: "CRYPTO_get_mem_debug_functions", dynlib: cryptodll.}
proc CRYPTO_malloc_locked*(num: cint; file: cstring; line: cint): pointer {.
    cdecl, importc: "CRYPTO_malloc_locked", dynlib: cryptodll.}
proc CRYPTO_free_locked*(pntr: pointer) {.cdecl, importc: "CRYPTO_free_locked", 
    dynlib: cryptodll.}
proc CRYPTO_malloc*(num: cint; file: cstring; line: cint): pointer {.cdecl, 
    importc: "CRYPTO_malloc", dynlib: cryptodll.}
proc CRYPTO_strdup*(str: cstring; file: cstring; line: cint): cstring {.cdecl, 
    importc: "CRYPTO_strdup", dynlib: cryptodll.}
proc CRYPTO_free*(pntr: pointer) {.cdecl, importc: "CRYPTO_free", 
                                  dynlib: cryptodll.}
proc CRYPTO_realloc*(address: pointer; num: cint; file: cstring; line: cint): pointer {.
    cdecl, importc: "CRYPTO_realloc", dynlib: cryptodll.}
proc CRYPTO_realloc_clean*(address: pointer; old_num: cint; num: cint; 
                           file: cstring; line: cint): pointer {.cdecl, 
    importc: "CRYPTO_realloc_clean", dynlib: cryptodll.}
proc CRYPTO_remalloc*(address: pointer; num: cint; file: cstring; line: cint): pointer {.
    cdecl, importc: "CRYPTO_remalloc", dynlib: cryptodll.}
proc OPENSSL_cleanse*(pntr: pointer; len: csize) {.cdecl, 
    importc: "OPENSSL_cleanse", dynlib: cryptodll.}
proc CRYPTO_set_mem_debug_options*(bits: clong) {.cdecl, 
    importc: "CRYPTO_set_mem_debug_options", dynlib: cryptodll.}
proc CRYPTO_get_mem_debug_options*(): clong {.cdecl, 
    importc: "CRYPTO_get_mem_debug_options", dynlib: cryptodll.}
proc CRYPTO_push_info*(info: cstring; file: cstring; line: cint): cint {.cdecl, 
    importc: "CRYPTO_push_info_", dynlib: cryptodll.}
proc CRYPTO_pop_info*(): cint {.cdecl, importc: "CRYPTO_pop_info", 
                                dynlib: cryptodll.}
proc CRYPTO_remove_all_info*(): cint {.cdecl, importc: "CRYPTO_remove_all_info", 
                                       dynlib: cryptodll.}
proc CRYPTO_dbg_malloc*(address: pointer; num: cint; file: cstring; line: cint; 
                        before_p: cint) {.cdecl, importc: "CRYPTO_dbg_malloc", 
    dynlib: cryptodll.}
proc CRYPTO_dbg_realloc*(addr1: pointer; addr2: pointer; num: cint; 
                         file: cstring; line: cint; before_p: cint) {.cdecl, 
    importc: "CRYPTO_dbg_realloc", dynlib: cryptodll.}
proc CRYPTO_dbg_free*(address: pointer; before_p: cint) {.cdecl, 
    importc: "CRYPTO_dbg_free", dynlib: cryptodll.}
proc CRYPTO_dbg_set_options*(bits: clong) {.cdecl, 
    importc: "CRYPTO_dbg_set_options", dynlib: cryptodll.}
proc CRYPTO_dbg_get_options*(): clong {.cdecl, 
                                        importc: "CRYPTO_dbg_get_options", 
                                        dynlib: cryptodll.}
proc CRYPTO_mem_leaks_fp*(a2: ptr FILE) {.cdecl, importc: "CRYPTO_mem_leaks_fp", 
    dynlib: cryptodll.}
proc CRYPTO_mem_leaks*(bio: ptr bio_st) {.cdecl, importc: "CRYPTO_mem_leaks", 
    dynlib: cryptodll.}


proc CRYPTO_mem_leaks_cb*(cb: ptr CRYPTO_MEM_LEAK_CB) {.cdecl, 
    importc: "CRYPTO_mem_leaks_cb", dynlib: cryptodll.}
proc OpenSSLDie*(file: cstring; line: cint; assertion: cstring) {.cdecl, 
    importc: "OpenSSLDie", dynlib: cryptodll.}
proc OPENSSL_ia32cap_loc*(): ptr culong {.cdecl, importc: "OPENSSL_ia32cap_loc", 
    dynlib: cryptodll.}
proc OPENSSL_isservice*(): cint {.cdecl, importc: "OPENSSL_isservice", 
                                  dynlib: cryptodll.}
proc FIPS_mode*(): cint {.cdecl, importc: "FIPS_mode", dynlib: cryptodll.}
proc FIPS_mode_set*(r: cint): cint {.cdecl, importc: "FIPS_mode_set", 
                                     dynlib: cryptodll.}
proc OPENSSL_init*() {.cdecl, importc: "OPENSSL_init", dynlib: cryptodll.}
proc CRYPTO_memcmp*(a: pointer; b: pointer; len: csize): cint {.cdecl, 
    importc: "CRYPTO_memcmp", dynlib: cryptodll.}
proc ERR_load_CRYPTO_strings*() {.cdecl, importc: "ERR_load_CRYPTO_strings", 
                                  dynlib: cryptodll.}

proc BIO_set_flags*(b: ptr BIO; flags: cint) {.cdecl, importc: "BIO_set_flags", 
    dynlib: cryptodll.}
proc BIO_test_flags*(b: ptr BIO; flags: cint): cint {.cdecl, 
    importc: "BIO_test_flags", dynlib: cryptodll.}
proc BIO_clear_flags*(b: ptr BIO; flags: cint) {.cdecl, 
    importc: "BIO_clear_flags", dynlib: cryptodll.}
#long (*BIO_get_callback(const BIO *b)) (struct bio_st *,int,const char *,int, long,long);

proc BIO_set_callback*(b: ptr BIO; callback: proc (a2: ptr bio_st; a3: cint; 
    a4: cstring; a5: cint; a6: clong; a7: clong): clong {.cdecl.}) {.cdecl, 
    importc: "BIO_set_callback", dynlib: cryptodll.}
proc BIO_get_callback_arg*(b: ptr BIO): cstring {.cdecl, 
    importc: "BIO_get_callback_arg", dynlib: cryptodll.}
proc BIO_set_callback_arg*(b: ptr BIO; arg: cstring) {.cdecl, 
    importc: "BIO_set_callback_arg", dynlib: cryptodll.}
proc BIO_method_name*(b: ptr BIO): cstring {.cdecl, importc: "BIO_method_name", 
    dynlib: cryptodll.}
proc BIO_method_type*(b: ptr BIO): cint {.cdecl, importc: "BIO_method_type", 
    dynlib: cryptodll.}

proc BIO_ctrl_pending*(b: ptr BIO): csize {.cdecl, importc: "BIO_ctrl_pending", 
    dynlib: cryptodll.}
proc BIO_ctrl_wpending*(b: ptr BIO): csize {.cdecl, 
    importc: "BIO_ctrl_wpending", dynlib: cryptodll.}
proc BIO_ctrl_get_write_guarantee*(b: ptr BIO): csize {.cdecl, 
    importc: "BIO_ctrl_get_write_guarantee", dynlib: cryptodll.}
proc BIO_ctrl_get_read_request*(b: ptr BIO): csize {.cdecl, 
    importc: "BIO_ctrl_get_read_request", dynlib: cryptodll.}
proc BIO_ctrl_reset_read_request*(b: ptr BIO): cint {.cdecl, 
    importc: "BIO_ctrl_reset_read_request", dynlib: cryptodll.}
proc BIO_set_ex_data*(bio: ptr BIO; idx: cint; data: pointer): cint {.cdecl, 
    importc: "BIO_set_ex_data", dynlib: cryptodll.}
proc BIO_get_ex_data*(bio: ptr BIO; idx: cint): pointer {.cdecl, 
    importc: "BIO_get_ex_data", dynlib: cryptodll.}
proc BIO_get_ex_new_index*(argl: clong; argp: pointer; 
                           new_func: ptr CRYPTO_EX_new; 
                           dup_func: ptr CRYPTO_EX_dup; 
                           free_func: ptr CRYPTO_EX_free): cint {.cdecl, 
    importc: "BIO_get_ex_new_index", dynlib: cryptodll.}
proc BIO_number_read*(bio: ptr BIO): culong {.cdecl, importc: "BIO_number_read", 
    dynlib: cryptodll.}
proc BIO_number_written*(bio: ptr BIO): culong {.cdecl, 
    importc: "BIO_number_written", dynlib: cryptodll.}
proc BIO_asn1_set_prefix*(b: ptr BIO; prefix: ptr asn1_ps_func; 
                          prefix_free: ptr asn1_ps_func): cint {.cdecl, 
    importc: "BIO_asn1_set_prefix", dynlib: cryptodll.}
proc BIO_asn1_get_prefix*(b: ptr BIO; pprefix: ptr ptr asn1_ps_func; 
                          pprefix_free: ptr ptr asn1_ps_func): cint {.cdecl, 
    importc: "BIO_asn1_get_prefix", dynlib: cryptodll.}
proc BIO_asn1_set_suffix*(b: ptr BIO; suffix: ptr asn1_ps_func; 
                          suffix_free: ptr asn1_ps_func): cint {.cdecl, 
    importc: "BIO_asn1_set_suffix", dynlib: cryptodll.}
proc BIO_asn1_get_suffix*(b: ptr BIO; psuffix: ptr ptr asn1_ps_func; 
                          psuffix_free: ptr ptr asn1_ps_func): cint {.cdecl, 
    importc: "BIO_asn1_get_suffix", dynlib: cryptodll.}
proc BIO_s_file*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_file", 
                                     dynlib: cryptodll.}
proc BIO_new_file*(filename: cstring; mode: cstring): ptr BIO {.cdecl, 
    importc: "BIO_new_file", dynlib: cryptodll.}
proc BIO_new_fp*(stream: ptr FILE; close_flag: cint): ptr BIO {.cdecl, 
    importc: "BIO_new_fp", dynlib: cryptodll.}
proc BIO_new*(typ: ptr BIO_METHOD): ptr BIO {.cdecl, importc: "BIO_new", 
    dynlib: cryptodll.}
proc BIO_set*(a: ptr BIO; typ: ptr BIO_METHOD): cint {.cdecl, 
    importc: "BIO_set", dynlib: cryptodll.}
proc BIO_free*(a: ptr BIO): cint {.cdecl, importc: "BIO_free", dynlib: cryptodll.}
proc BIO_vfree*(a: ptr BIO) {.cdecl, importc: "BIO_vfree", dynlib: cryptodll.}
proc BIO_read*(b: ptr BIO; data: pointer; len: cint): cint {.cdecl, 
    importc: "BIO_read", dynlib: cryptodll.}
proc BIO_gets*(bp: ptr BIO; buf: cstring; size: cint): cint {.cdecl, 
    importc: "BIO_gets", dynlib: cryptodll.}
proc BIO_write*(b: ptr BIO; data: pointer; len: cint): cint {.cdecl, 
    importc: "BIO_write", dynlib: cryptodll.}
proc BIO_puts*(bp: ptr BIO; buf: cstring): cint {.cdecl, importc: "BIO_puts", 
    dynlib: cryptodll.}
proc BIO_indent*(b: ptr BIO; indent: cint; max: cint): cint {.cdecl, 
    importc: "BIO_indent", dynlib: cryptodll.}
proc BIO_ctrl*(bp: ptr BIO; cmd: cint; larg: clong; parg: pointer): clong {.
    cdecl, importc: "BIO_ctrl", dynlib: cryptodll.}
proc BIO_callback_ctrl*(b: ptr BIO; cmd: cint; fp: proc (a2: ptr bio_st; 
    a3: cint; a4: cstring; a5: cint; a6: clong; a7: clong) {.cdecl.}): clong {.
    cdecl, importc: "BIO_callback_ctrl", dynlib: cryptodll.}
proc BIO_ptr_ctrl*(bp: ptr BIO; cmd: cint; larg: clong): cstring {.cdecl, 
    importc: "BIO_ptr_ctrl", dynlib: cryptodll.}
proc BIO_int_ctrl*(bp: ptr BIO; cmd: cint; larg: clong; iarg: cint): clong {.
    cdecl, importc: "BIO_int_ctrl", dynlib: cryptodll.}
proc BIO_push*(b: ptr BIO; append: ptr BIO): ptr BIO {.cdecl, 
    importc: "BIO_push", dynlib: cryptodll.}
proc BIO_pop*(b: ptr BIO): ptr BIO {.cdecl, importc: "BIO_pop", 
                                     dynlib: cryptodll.}
proc BIO_free_all*(a: ptr BIO) {.cdecl, importc: "BIO_free_all", 
                                 dynlib: cryptodll.}
proc BIO_find_type*(b: ptr BIO; bio_typ: cint): ptr BIO {.cdecl, 
    importc: "BIO_find_type", dynlib: cryptodll.}
proc BIO_next*(b: ptr BIO): ptr BIO {.cdecl, importc: "BIO_next", 
                                      dynlib: cryptodll.}
proc BIO_get_retry_BIO*(bio: ptr BIO; reason: ptr cint): ptr BIO {.cdecl, 
    importc: "BIO_get_retry_BIO", dynlib: cryptodll.}
proc BIO_get_retry_reason*(bio: ptr BIO): cint {.cdecl, 
    importc: "BIO_get_retry_reason", dynlib: cryptodll.}
proc BIO_dup_chain*(input: ptr BIO): ptr BIO {.cdecl, importc: "BIO_dup_chain", 
    dynlib: cryptodll.}
proc BIO_nread0*(bio: ptr BIO; buf: cstringArray): cint {.cdecl, 
    importc: "BIO_nread0", dynlib: cryptodll.}
proc BIO_nread*(bio: ptr BIO; buf: cstringArray; num: cint): cint {.cdecl, 
    importc: "BIO_nread", dynlib: cryptodll.}
proc BIO_nwrite0*(bio: ptr BIO; buf: cstringArray): cint {.cdecl, 
    importc: "BIO_nwrite0", dynlib: cryptodll.}
proc BIO_nwrite*(bio: ptr BIO; buf: cstringArray; num: cint): cint {.cdecl, 
    importc: "BIO_nwrite", dynlib: cryptodll.}
proc BIO_debug_callback*(bio: ptr BIO; cmd: cint; argp: cstring; argi: cint; 
                         argl: clong; ret: clong): clong {.cdecl, 
    importc: "BIO_debug_callback", dynlib: cryptodll.}
proc BIO_s_mem*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_mem", 
                                    dynlib: cryptodll.}
proc BIO_new_mem_buf*(buf: pointer; len: cint): ptr BIO {.cdecl, 
    importc: "BIO_new_mem_buf", dynlib: cryptodll.}
proc BIO_s_socket*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_socket", 
                                       dynlib: cryptodll.}
proc BIO_s_connect*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_connect", 
                                        dynlib: cryptodll.}
proc BIO_s_accept*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_accept", 
                                       dynlib: cryptodll.}
proc BIO_s_fd*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_fd", dynlib: cryptodll.}
proc BIO_s_log*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_log", 
                                    dynlib: cryptodll.}
proc BIO_s_bio*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_bio", 
                                    dynlib: cryptodll.}
proc BIO_s_null*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_null", 
                                     dynlib: cryptodll.}
proc BIO_f_null*(): ptr BIO_METHOD {.cdecl, importc: "BIO_f_null", 
                                     dynlib: cryptodll.}
proc BIO_f_buffer*(): ptr BIO_METHOD {.cdecl, importc: "BIO_f_buffer", 
                                       dynlib: cryptodll.}
proc BIO_f_nbio_test*(): ptr BIO_METHOD {.cdecl, importc: "BIO_f_nbio_test", 
    dynlib: cryptodll.}
proc BIO_s_datagram*(): ptr BIO_METHOD {.cdecl, importc: "BIO_s_datagram", 
    dynlib: cryptodll.}
proc BIO_sock_should_retry*(i: cint): cint {.cdecl, 
    importc: "BIO_sock_should_retry", dynlib: cryptodll.}
proc BIO_sock_non_fatal_error*(error: cint): cint {.cdecl, 
    importc: "BIO_sock_non_fatal_error", dynlib: cryptodll.}
proc BIO_dgram_non_fatal_error*(error: cint): cint {.cdecl, 
    importc: "BIO_dgram_non_fatal_error", dynlib: cryptodll.}
proc BIO_fd_should_retry*(i: cint): cint {.cdecl, 
    importc: "BIO_fd_should_retry", dynlib: cryptodll.}
proc BIO_fd_non_fatal_error*(error: cint): cint {.cdecl, 
    importc: "BIO_fd_non_fatal_error", dynlib: cryptodll.}
proc BIO_dump_cb*(cb: proc (data: pointer; len: csize; u: pointer): cint {.cdecl.}; 
                  u: pointer; s: cstring; len: cint): cint {.cdecl, 
    importc: "BIO_dump_cb", dynlib: cryptodll.}
proc BIO_dump_indent_cb*(cb: proc (data: pointer; len: csize; u: pointer): cint {.
    cdecl.}; u: pointer; s: cstring; len: cint; indent: cint): cint {.cdecl, 
    importc: "BIO_dump_indent_cb", dynlib: cryptodll.}
proc BIO_dump*(b: ptr BIO; bytes: cstring; len: cint): cint {.cdecl, 
    importc: "BIO_dump", dynlib: cryptodll.}
proc BIO_dump_indent*(b: ptr BIO; bytes: cstring; len: cint; indent: cint): cint {.
    cdecl, importc: "BIO_dump_indent", dynlib: cryptodll.}
proc BIO_dump_fp*(fp: ptr FILE; s: cstring; len: cint): cint {.cdecl, 
    importc: "BIO_dump_fp", dynlib: cryptodll.}
proc BIO_dump_indent_fp*(fp: ptr FILE; s: cstring; len: cint; indent: cint): cint {.
    cdecl, importc: "BIO_dump_indent_fp", dynlib: cryptodll.}
proc BIO_gethostbyname*(name: cstring): ptr hostent {.cdecl, 
    importc: "BIO_gethostbyname", dynlib: cryptodll.}
proc BIO_sock_error*(sock: cint): cint {.cdecl, importc: "BIO_sock_error", 
    dynlib: cryptodll.}
proc BIO_socket_ioctl*(fd: cint; typ: clong; arg: pointer): cint {.cdecl, 
    importc: "BIO_socket_ioctl", dynlib: cryptodll.}
proc BIO_socket_nbio*(fd: cint; mode: cint): cint {.cdecl, 
    importc: "BIO_socket_nbio", dynlib: cryptodll.}
proc BIO_get_port*(str: cstring; port_pntr: ptr cushort): cint {.cdecl, 
    importc: "BIO_get_port", dynlib: cryptodll.}
proc BIO_get_host_ip*(str: cstring; ip: ptr cuchar): cint {.cdecl, 
    importc: "BIO_get_host_ip", dynlib: cryptodll.}
proc BIO_get_accept_socket*(host_port: cstring; mode: cint): cint {.cdecl, 
    importc: "BIO_get_accept_socket", dynlib: cryptodll.}
proc BIO_accept*(sock: cint; ip_port: cstringArray): cint {.cdecl, 
    importc: "BIO_accept", dynlib: cryptodll.}
proc BIO_sock_init*(): cint {.cdecl, importc: "BIO_sock_init", dynlib: cryptodll.}
proc BIO_sock_cleanup*() {.cdecl, importc: "BIO_sock_cleanup", dynlib: cryptodll.}
proc BIO_set_tcp_ndelay*(sock: cint; turn_on: cint): cint {.cdecl, 
    importc: "BIO_set_tcp_ndelay", dynlib: cryptodll.}
proc BIO_new_socket*(sock: cint; close_flag: cint): ptr BIO {.cdecl, 
    importc: "BIO_new_socket", dynlib: cryptodll.}
proc BIO_new_dgram*(fd: cint; close_flag: cint): ptr BIO {.cdecl, 
    importc: "BIO_new_dgram", dynlib: cryptodll.}
proc BIO_new_fd*(fd: cint; close_flag: cint): ptr BIO {.cdecl, 
    importc: "BIO_new_fd", dynlib: cryptodll.}
proc BIO_new_connect*(host_port: cstring): ptr BIO {.cdecl, 
    importc: "BIO_new_connect", dynlib: cryptodll.}
proc BIO_new_accept*(host_port: cstring): ptr BIO {.cdecl, 
    importc: "BIO_new_accept", dynlib: cryptodll.}
proc BIO_new_bio_pair*(bio1: ptr ptr BIO; writebuf1: csize; bio2: ptr ptr BIO; 
                       writebuf2: csize): cint {.cdecl, 
    importc: "BIO_new_bio_pair", dynlib: cryptodll.}
proc BIO_copy_next_retry*(b: ptr BIO) {.cdecl, importc: "BIO_copy_next_retry", 
                                        dynlib: cryptodll.}
#int BIO_printf(BIO *bio, const char *format, ...)
# __attribute__((__format__(__printf__,2,3)));
#int BIO_vprintf(BIO *bio, const char *format, va_list args)
# __attribute__((__format__(__printf__,2,0)));
#int BIO_snprintf(char *buf, size_t n, const char *format, ...)
# __attribute__((__format__(__printf__,3,4)));
#int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
# __attribute__((__format__(__printf__,3,0)));

proc ERR_load_BIO_strings*() {.cdecl, importc: "ERR_load_BIO_strings", 
                               dynlib: cryptodll.}

proc BN_GENCB_call*(cb: ptr BN_GENCB; a: cint; b: cint): cint {.cdecl, 
    importc: "BN_GENCB_call", dynlib: cryptodll.}
proc BN_value_one*(): ptr BIGNUM {.cdecl, importc: "BN_value_one", 
                                   dynlib: cryptodll.}
proc BN_options*(): cstring {.cdecl, importc: "BN_options", dynlib: cryptodll.}
proc BN_CTX_new*(): ptr BN_CTX {.cdecl, importc: "BN_CTX_new", dynlib: cryptodll.}
proc BN_CTX_init*(c: ptr BN_CTX) {.cdecl, importc: "BN_CTX_init", 
                                   dynlib: cryptodll.}
proc BN_CTX_free*(c: ptr BN_CTX) {.cdecl, importc: "BN_CTX_free", 
                                   dynlib: cryptodll.}
proc BN_CTX_start*(ctx: ptr BN_CTX) {.cdecl, importc: "BN_CTX_start", 
                                      dynlib: cryptodll.}
proc BN_CTX_get*(ctx: ptr BN_CTX): ptr BIGNUM {.cdecl, importc: "BN_CTX_get", 
    dynlib: cryptodll.}
proc BN_CTX_end*(ctx: ptr BN_CTX) {.cdecl, importc: "BN_CTX_end", 
                                    dynlib: cryptodll.}
proc BN_rand*(rnd: ptr BIGNUM; bits: cint; top: cint; bottom: cint): cint {.
    cdecl, importc: "BN_rand", dynlib: cryptodll.}
proc BN_pseudo_rand*(rnd: ptr BIGNUM; bits: cint; top: cint; bottom: cint): cint {.
    cdecl, importc: "BN_pseudo_rand", dynlib: cryptodll.}
proc BN_rand_range*(rnd: ptr BIGNUM; range: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_rand_range", dynlib: cryptodll.}
proc BN_pseudo_rand_range*(rnd: ptr BIGNUM; range: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_pseudo_rand_range", dynlib: cryptodll.}
proc BN_num_bits*(a: ptr BIGNUM): cint {.cdecl, importc: "BN_num_bits", 
    dynlib: cryptodll.}
proc BN_num_bits_word*(a2: culong): cint {.cdecl, importc: "BN_num_bits_word", 
    dynlib: cryptodll.}
proc BN_new*(): ptr BIGNUM {.cdecl, importc: "BN_new", dynlib: cryptodll.}
proc BN_init*(a2: ptr BIGNUM) {.cdecl, importc: "BN_init", dynlib: cryptodll.}
proc BN_clear_free*(a: ptr BIGNUM) {.cdecl, importc: "BN_clear_free", 
                                     dynlib: cryptodll.}
proc BN_copy*(a: ptr BIGNUM; b: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "BN_copy", dynlib: cryptodll.}
proc BN_swap*(a: ptr BIGNUM; b: ptr BIGNUM) {.cdecl, importc: "BN_swap", 
    dynlib: cryptodll.}
proc BN_bin2bn*(s: ptr cuchar; len: cint; ret: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "BN_bin2bn", dynlib: cryptodll.}
proc BN_bn2bin*(a: ptr BIGNUM; to: ptr cuchar): cint {.cdecl, 
    importc: "BN_bn2bin", dynlib: cryptodll.}
proc BN_mpi2bn*(s: ptr cuchar; len: cint; ret: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "BN_mpi2bn", dynlib: cryptodll.}
proc BN_bn2mpi*(a: ptr BIGNUM; to: ptr cuchar): cint {.cdecl, 
    importc: "BN_bn2mpi", dynlib: cryptodll.}
proc BN_sub*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_sub", dynlib: cryptodll.}
proc BN_usub*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_usub", dynlib: cryptodll.}
proc BN_uadd*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_uadd", dynlib: cryptodll.}
proc BN_add*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_add", dynlib: cryptodll.}
proc BN_mul*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_mul", dynlib: cryptodll.}
proc BN_sqr*(r: ptr BIGNUM; a: ptr BIGNUM; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_sqr", dynlib: cryptodll.}
proc BN_set_negative*(b: ptr BIGNUM; n: cint) {.cdecl, 
    importc: "BN_set_negative", dynlib: cryptodll.}
proc BN_div*(dv: ptr BIGNUM; rem: ptr BIGNUM; m: ptr BIGNUM; d: ptr BIGNUM; 
             ctx: ptr BN_CTX): cint {.cdecl, importc: "BN_div", 
                                      dynlib: cryptodll.}
proc BN_nnmod*(r: ptr BIGNUM; m: ptr BIGNUM; d: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_nnmod", dynlib: cryptodll.}
proc BN_mod_add*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; m: ptr BIGNUM; 
                 ctx: ptr BN_CTX): cint {.cdecl, importc: "BN_mod_add", 
    dynlib: cryptodll.}
proc BN_mod_add_quick*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                       m: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_mod_add_quick", dynlib: cryptodll.}
proc BN_mod_sub*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; m: ptr BIGNUM; 
                 ctx: ptr BN_CTX): cint {.cdecl, importc: "BN_mod_sub", 
    dynlib: cryptodll.}
proc BN_mod_sub_quick*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                       m: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_mod_sub_quick", dynlib: cryptodll.}
proc BN_mod_mul*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; m: ptr BIGNUM; 
                 ctx: ptr BN_CTX): cint {.cdecl, importc: "BN_mod_mul", 
    dynlib: cryptodll.}
proc BN_mod_sqr*(r: ptr BIGNUM; a: ptr BIGNUM; m: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_mod_sqr", dynlib: cryptodll.}
proc BN_mod_lshift1*(r: ptr BIGNUM; a: ptr BIGNUM; m: ptr BIGNUM; 
                     ctx: ptr BN_CTX): cint {.cdecl, importc: "BN_mod_lshift1", 
    dynlib: cryptodll.}
proc BN_mod_lshift1_quick*(r: ptr BIGNUM; a: ptr BIGNUM; m: ptr BIGNUM): cint {.
    cdecl, importc: "BN_mod_lshift1_quick", dynlib: cryptodll.}
proc BN_mod_lshift*(r: ptr BIGNUM; a: ptr BIGNUM; n: cint; m: ptr BIGNUM; 
                    ctx: ptr BN_CTX): cint {.cdecl, importc: "BN_mod_lshift", 
    dynlib: cryptodll.}
proc BN_mod_lshift_quick*(r: ptr BIGNUM; a: ptr BIGNUM; n: cint; m: ptr BIGNUM): cint {.
    cdecl, importc: "BN_mod_lshift_quick", dynlib: cryptodll.}
proc BN_mod_word*(a: ptr BIGNUM; w: culong): culong {.cdecl, 
    importc: "BN_mod_word", dynlib: cryptodll.}
proc BN_div_word*(a: ptr BIGNUM; w: culong): culong {.cdecl, 
    importc: "BN_div_word", dynlib: cryptodll.}
proc BN_mul_word*(a: ptr BIGNUM; w: culong): cint {.cdecl, 
    importc: "BN_mul_word", dynlib: cryptodll.}
proc BN_add_word*(a: ptr BIGNUM; w: culong): cint {.cdecl, 
    importc: "BN_add_word", dynlib: cryptodll.}
proc BN_sub_word*(a: ptr BIGNUM; w: culong): cint {.cdecl, 
    importc: "BN_sub_word", dynlib: cryptodll.}
proc BN_set_word*(a: ptr BIGNUM; w: culong): cint {.cdecl, 
    importc: "BN_set_word", dynlib: cryptodll.}
proc BN_get_word*(a: ptr BIGNUM): culong {.cdecl, importc: "BN_get_word", 
    dynlib: cryptodll.}
proc BN_cmp*(a: ptr BIGNUM; b: ptr BIGNUM): cint {.cdecl, importc: "BN_cmp", 
    dynlib: cryptodll.}
proc BN_free*(a: ptr BIGNUM) {.cdecl, importc: "BN_free", dynlib: cryptodll.}
proc BN_is_bit_set*(a: ptr BIGNUM; n: cint): cint {.cdecl, 
    importc: "BN_is_bit_set", dynlib: cryptodll.}
proc BN_lshift*(r: ptr BIGNUM; a: ptr BIGNUM; n: cint): cint {.cdecl, 
    importc: "BN_lshift", dynlib: cryptodll.}
proc BN_lshift1*(r: ptr BIGNUM; a: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_lshift1", dynlib: cryptodll.}
proc BN_exp*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_exp", dynlib: cryptodll.}
proc BN_mod_exp*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; m: ptr BIGNUM; 
                 ctx: ptr BN_CTX): cint {.cdecl, importc: "BN_mod_exp", 
    dynlib: cryptodll.}
proc BN_mod_exp_mont*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      m: ptr BIGNUM; ctx: ptr BN_CTX; m_ctx: ptr BN_MONT_CTX): cint {.
    cdecl, importc: "BN_mod_exp_mont", dynlib: cryptodll.}
proc BN_mod_exp_mont_consttime*(rr: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                                m: ptr BIGNUM; ctx: ptr BN_CTX; 
                                in_mont: ptr BN_MONT_CTX): cint {.cdecl, 
    importc: "BN_mod_exp_mont_consttime", dynlib: cryptodll.}
proc BN_mod_exp_mont_word*(r: ptr BIGNUM; a: culong; p: ptr BIGNUM; 
                           m: ptr BIGNUM; ctx: ptr BN_CTX; 
                           m_ctx: ptr BN_MONT_CTX): cint {.cdecl, 
    importc: "BN_mod_exp_mont_word", dynlib: cryptodll.}
proc BN_mod_exp2_mont*(r: ptr BIGNUM; a1: ptr BIGNUM; p1: ptr BIGNUM; 
                       a2: ptr BIGNUM; p2: ptr BIGNUM; m: ptr BIGNUM; 
                       ctx: ptr BN_CTX; m_ctx: ptr BN_MONT_CTX): cint {.cdecl, 
    importc: "BN_mod_exp2_mont", dynlib: cryptodll.}
proc BN_mod_exp_simple*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                        m: ptr BIGNUM; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_mod_exp_simple", dynlib: cryptodll.}
proc BN_mask_bits*(a: ptr BIGNUM; n: cint): cint {.cdecl, 
    importc: "BN_mask_bits", dynlib: cryptodll.}
proc BN_print_fp*(fp: ptr FILE; a: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_print_fp", dynlib: cryptodll.}
proc BN_print*(fp: ptr BIO; a: ptr BIGNUM): cint {.cdecl, importc: "BN_print", 
    dynlib: cryptodll.}
proc BN_reciprocal*(r: ptr BIGNUM; m: ptr BIGNUM; len: cint; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_reciprocal", dynlib: cryptodll.}
proc BN_rshift*(r: ptr BIGNUM; a: ptr BIGNUM; n: cint): cint {.cdecl, 
    importc: "BN_rshift", dynlib: cryptodll.}
proc BN_rshift1*(r: ptr BIGNUM; a: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_rshift1", dynlib: cryptodll.}
proc BN_clear*(a: ptr BIGNUM) {.cdecl, importc: "BN_clear", dynlib: cryptodll.}
proc BN_dup*(a: ptr BIGNUM): ptr BIGNUM {.cdecl, importc: "BN_dup", 
    dynlib: cryptodll.}
proc BN_ucmp*(a: ptr BIGNUM; b: ptr BIGNUM): cint {.cdecl, importc: "BN_ucmp", 
    dynlib: cryptodll.}
proc BN_set_bit*(a: ptr BIGNUM; n: cint): cint {.cdecl, importc: "BN_set_bit", 
    dynlib: cryptodll.}
proc BN_clear_bit*(a: ptr BIGNUM; n: cint): cint {.cdecl, 
    importc: "BN_clear_bit", dynlib: cryptodll.}
proc BN_bn2hex*(a: ptr BIGNUM): cstring {.cdecl, importc: "BN_bn2hex", 
    dynlib: cryptodll.}
proc BN_bn2dec*(a: ptr BIGNUM): cstring {.cdecl, importc: "BN_bn2dec", 
    dynlib: cryptodll.}
proc BN_hex2bn*(a: ptr ptr BIGNUM; str: cstring): cint {.cdecl, 
    importc: "BN_hex2bn", dynlib: cryptodll.}
proc BN_dec2bn*(a: ptr ptr BIGNUM; str: cstring): cint {.cdecl, 
    importc: "BN_dec2bn", dynlib: cryptodll.}
proc BN_asc2bn*(a: ptr ptr BIGNUM; str: cstring): cint {.cdecl, 
    importc: "BN_asc2bn", dynlib: cryptodll.}
proc BN_gcd*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_gcd", dynlib: cryptodll.}
proc BN_kronecker*(a: ptr BIGNUM; b: ptr BIGNUM; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_kronecker", dynlib: cryptodll.}
proc BN_mod_inverse*(ret: ptr BIGNUM; a: ptr BIGNUM; n: ptr BIGNUM; 
                     ctx: ptr BN_CTX): ptr BIGNUM {.cdecl, 
    importc: "BN_mod_inverse", dynlib: cryptodll.}
proc BN_mod_sqrt*(ret: ptr BIGNUM; a: ptr BIGNUM; n: ptr BIGNUM; ctx: ptr BN_CTX): ptr BIGNUM {.
    cdecl, importc: "BN_mod_sqrt", dynlib: cryptodll.}
proc BN_consttime_swap*(swap: culong; a: ptr BIGNUM; b: ptr BIGNUM; nwords: cint) {.
    cdecl, importc: "BN_consttime_swap", dynlib: cryptodll.}
proc BN_generate_prime*(ret: ptr BIGNUM; bits: cint; safe: cint; 
                        add: ptr BIGNUM; rem: ptr BIGNUM; callback: proc (
    a2: cint; a3: cint; a4: pointer) {.cdecl.}; cb_arg: pointer): ptr BIGNUM {.
    cdecl, importc: "BN_generate_prime", dynlib: cryptodll.}
proc BN_is_prime*(p: ptr BIGNUM; nchecks: cint; 
                  callback: proc (a2: cint; a3: cint; a4: pointer) {.cdecl.}; 
                  ctx: ptr BN_CTX; cb_arg: pointer): cint {.cdecl, 
    importc: "BN_is_prime", dynlib: cryptodll.}
proc BN_is_prime_fasttest*(p: ptr BIGNUM; nchecks: cint; callback: proc (
    a2: cint; a3: cint; a4: pointer) {.cdecl.}; ctx: ptr BN_CTX; 
                           cb_arg: pointer; do_trial_division: cint): cint {.
    cdecl, importc: "BN_is_prime_fasttest", dynlib: cryptodll.}
proc BN_generate_prime_ex*(ret: ptr BIGNUM; bits: cint; safe: cint; 
                           add: ptr BIGNUM; rem: ptr BIGNUM; cb: ptr BN_GENCB): cint {.
    cdecl, importc: "BN_generate_prime_ex", dynlib: cryptodll.}
proc BN_is_prime_ex*(p: ptr BIGNUM; nchecks: cint; ctx: ptr BN_CTX; 
                     cb: ptr BN_GENCB): cint {.cdecl, importc: "BN_is_prime_ex", 
    dynlib: cryptodll.}
proc BN_is_prime_fasttest_ex*(p: ptr BIGNUM; nchecks: cint; ctx: ptr BN_CTX; 
                              do_trial_division: cint; cb: ptr BN_GENCB): cint {.
    cdecl, importc: "BN_is_prime_fasttest_ex", dynlib: cryptodll.}
proc BN_X931_generate_Xpq*(Xp: ptr BIGNUM; Xq: ptr BIGNUM; nbits: cint; 
                           ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_X931_generate_Xpq", dynlib: cryptodll.}
proc BN_X931_derive_prime_ex*(p: ptr BIGNUM; p1: ptr BIGNUM; p2: ptr BIGNUM; 
                              Xp: ptr BIGNUM; Xp1: ptr BIGNUM; Xp2: ptr BIGNUM; 
                              e: ptr BIGNUM; ctx: ptr BN_CTX; cb: ptr BN_GENCB): cint {.
    cdecl, importc: "BN_X931_derive_prime_ex", dynlib: cryptodll.}
proc BN_X931_generate_prime_ex*(p: ptr BIGNUM; p1: ptr BIGNUM; p2: ptr BIGNUM; 
                                Xp1: ptr BIGNUM; Xp2: ptr BIGNUM; 
                                Xp: ptr BIGNUM; e: ptr BIGNUM; ctx: ptr BN_CTX; 
                                cb: ptr BN_GENCB): cint {.cdecl, 
    importc: "BN_X931_generate_prime_ex", dynlib: cryptodll.}
proc BN_MONT_CTX_new*(): ptr BN_MONT_CTX {.cdecl, importc: "BN_MONT_CTX_new", 
    dynlib: cryptodll.}
proc BN_MONT_CTX_init*(ctx: ptr BN_MONT_CTX) {.cdecl, 
    importc: "BN_MONT_CTX_init", dynlib: cryptodll.}
proc BN_mod_mul_montgomery*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                            mont: ptr BN_MONT_CTX; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_mod_mul_montgomery", dynlib: cryptodll.}
proc BN_from_montgomery*(r: ptr BIGNUM; a: ptr BIGNUM; mont: ptr BN_MONT_CTX; 
                         ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_from_montgomery", dynlib: cryptodll.}
proc BN_MONT_CTX_free*(mont: ptr BN_MONT_CTX) {.cdecl, 
    importc: "BN_MONT_CTX_free", dynlib: cryptodll.}
proc BN_MONT_CTX_set*(mont: ptr BN_MONT_CTX; modulus: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_MONT_CTX_set", dynlib: cryptodll.}
proc BN_MONT_CTX_copy*(to: ptr BN_MONT_CTX; frm: ptr BN_MONT_CTX): ptr BN_MONT_CTX {.
    cdecl, importc: "BN_MONT_CTX_copy", dynlib: cryptodll.}
proc BN_MONT_CTX_set_locked*(pmont: ptr ptr BN_MONT_CTX; lock: cint; 
                             modulus: ptr BIGNUM; ctx: ptr BN_CTX): ptr BN_MONT_CTX {.
    cdecl, importc: "BN_MONT_CTX_set_locked", dynlib: cryptodll.}
proc BN_BLINDING_new*(A: ptr BIGNUM; Ai: ptr BIGNUM; modulus: ptr BIGNUM): ptr BN_BLINDING {.
    cdecl, importc: "BN_BLINDING_new", dynlib: cryptodll.}
proc BN_BLINDING_free*(b: ptr BN_BLINDING) {.cdecl, importc: "BN_BLINDING_free", 
    dynlib: cryptodll.}
proc BN_BLINDING_update*(b: ptr BN_BLINDING; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_BLINDING_update", dynlib: cryptodll.}
proc BN_BLINDING_convert*(n: ptr BIGNUM; b: ptr BN_BLINDING; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_BLINDING_convert", dynlib: cryptodll.}
proc BN_BLINDING_invert*(n: ptr BIGNUM; b: ptr BN_BLINDING; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_BLINDING_invert", dynlib: cryptodll.}
proc BN_BLINDING_convert_ex*(n: ptr BIGNUM; r: ptr BIGNUM; b: ptr BN_BLINDING; 
                             a5: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_BLINDING_convert_ex", dynlib: cryptodll.}
proc BN_BLINDING_invert_ex*(n: ptr BIGNUM; r: ptr BIGNUM; b: ptr BN_BLINDING; 
                            a5: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_BLINDING_invert_ex", dynlib: cryptodll.}
proc BN_BLINDING_get_thread_id*(a2: ptr BN_BLINDING): culong {.cdecl, 
    importc: "BN_BLINDING_get_thread_id", dynlib: cryptodll.}
proc BN_BLINDING_set_thread_id*(a2: ptr BN_BLINDING; a3: culong) {.cdecl, 
    importc: "BN_BLINDING_set_thread_id", dynlib: cryptodll.}
proc BN_BLINDING_thread_id*(a2: ptr BN_BLINDING): ptr CRYPTO_THREADID_OBJ {.cdecl, 
    importc: "BN_BLINDING_thread_id", dynlib: cryptodll.}
proc BN_BLINDING_get_flags*(a2: ptr BN_BLINDING): culong {.cdecl, 
    importc: "BN_BLINDING_get_flags", dynlib: cryptodll.}
proc BN_BLINDING_set_flags*(a2: ptr BN_BLINDING; a3: culong) {.cdecl, 
    importc: "BN_BLINDING_set_flags", dynlib: cryptodll.}
proc BN_BLINDING_create_param*(b: ptr BN_BLINDING; e: ptr BIGNUM; m: ptr BIGNUM; 
                               ctx: ptr BN_CTX; bn_mod_exp: proc (r: ptr BIGNUM; 
    a: ptr BIGNUM; p: ptr BIGNUM; m: ptr BIGNUM; ctx: ptr BN_CTX; 
    m_ctx: ptr BN_MONT_CTX): cint {.cdecl.}; m_ctx: ptr BN_MONT_CTX): ptr BN_BLINDING {.
    cdecl, importc: "BN_BLINDING_create_param", dynlib: cryptodll.}
proc BN_set_params*(mul: cint; high: cint; low: cint; mont: cint) {.cdecl, 
    importc: "BN_set_params", dynlib: cryptodll.}
proc BN_get_params*(which: cint): cint {.cdecl, importc: "BN_get_params", 
    dynlib: cryptodll.}
proc BN_RECP_CTX_init*(recp: ptr BN_RECP_CTX) {.cdecl, 
    importc: "BN_RECP_CTX_init", dynlib: cryptodll.}
proc BN_RECP_CTX_new*(): ptr BN_RECP_CTX {.cdecl, importc: "BN_RECP_CTX_new", 
    dynlib: cryptodll.}
proc BN_RECP_CTX_free*(recp: ptr BN_RECP_CTX) {.cdecl, 
    importc: "BN_RECP_CTX_free", dynlib: cryptodll.}
proc BN_RECP_CTX_set*(recp: ptr BN_RECP_CTX; rdiv: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_RECP_CTX_set", dynlib: cryptodll.}
proc BN_mod_mul_reciprocal*(r: ptr BIGNUM; x: ptr BIGNUM; y: ptr BIGNUM; 
                            recp: ptr BN_RECP_CTX; ctx: ptr BN_CTX): cint {.
    cdecl, importc: "BN_mod_mul_reciprocal", dynlib: cryptodll.}
proc BN_mod_exp_recp*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      m: ptr BIGNUM; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_mod_exp_recp", dynlib: cryptodll.}
proc BN_div_recp*(dv: ptr BIGNUM; rem: ptr BIGNUM; m: ptr BIGNUM; 
                  recp: ptr BN_RECP_CTX; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_div_recp", dynlib: cryptodll.}
proc BN_GF2m_add*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_GF2m_add", dynlib: cryptodll.}
proc BN_GF2m_mod*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_GF2m_mod", dynlib: cryptodll.}
proc BN_GF2m_mod_mul*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                      p: ptr BIGNUM; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_mul", dynlib: cryptodll.}
proc BN_GF2m_mod_sqr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_sqr", dynlib: cryptodll.}
proc BN_GF2m_mod_inv*(r: ptr BIGNUM; b: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_inv", dynlib: cryptodll.}
proc BN_GF2m_mod_div*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                      p: ptr BIGNUM; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_div", dynlib: cryptodll.}
proc BN_GF2m_mod_exp*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                      p: ptr BIGNUM; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_exp", dynlib: cryptodll.}
proc BN_GF2m_mod_sqrt*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                       ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_sqrt", dynlib: cryptodll.}
proc BN_GF2m_mod_solve_quad*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                             ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_solve_quad", dynlib: cryptodll.}
proc BN_GF2m_mod_arr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr cint): cint {.cdecl, 
    importc: "BN_GF2m_mod_arr", dynlib: cryptodll.}
proc BN_GF2m_mod_mul_arr*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                          p: ptr cint; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_mul_arr", dynlib: cryptodll.}
proc BN_GF2m_mod_sqr_arr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr cint; 
                          ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_sqr_arr", dynlib: cryptodll.}
proc BN_GF2m_mod_inv_arr*(r: ptr BIGNUM; b: ptr BIGNUM; p: ptr cint; 
                          ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_inv_arr", dynlib: cryptodll.}
proc BN_GF2m_mod_div_arr*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                          p: ptr cint; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_div_arr", dynlib: cryptodll.}
proc BN_GF2m_mod_exp_arr*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                          p: ptr cint; ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_exp_arr", dynlib: cryptodll.}
proc BN_GF2m_mod_sqrt_arr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr cint; 
                           ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_sqrt_arr", dynlib: cryptodll.}
proc BN_GF2m_mod_solve_quad_arr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr cint; 
                                 ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_GF2m_mod_solve_quad_arr", dynlib: cryptodll.}
proc BN_GF2m_poly2arr*(a: ptr BIGNUM; p: ptr cint; max: cint): cint {.cdecl, 
    importc: "BN_GF2m_poly2arr", dynlib: cryptodll.}
proc BN_GF2m_arr2poly*(p: ptr cint; a: ptr BIGNUM): cint {.cdecl, 
    importc: "BN_GF2m_arr2poly", dynlib: cryptodll.}
proc BN_nist_mod_192*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_nist_mod_192", dynlib: cryptodll.}
proc BN_nist_mod_224*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_nist_mod_224", dynlib: cryptodll.}
proc BN_nist_mod_256*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_nist_mod_256", dynlib: cryptodll.}
proc BN_nist_mod_384*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_nist_mod_384", dynlib: cryptodll.}
proc BN_nist_mod_521*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.cdecl, 
    importc: "BN_nist_mod_521", dynlib: cryptodll.}
proc BN_get0_nist_prime_192*(): ptr BIGNUM {.cdecl, 
    importc: "BN_get0_nist_prime_192", dynlib: cryptodll.}
proc BN_get0_nist_prime_224*(): ptr BIGNUM {.cdecl, 
    importc: "BN_get0_nist_prime_224", dynlib: cryptodll.}
proc BN_get0_nist_prime_256*(): ptr BIGNUM {.cdecl, 
    importc: "BN_get0_nist_prime_256", dynlib: cryptodll.}
proc BN_get0_nist_prime_384*(): ptr BIGNUM {.cdecl, 
    importc: "BN_get0_nist_prime_384", dynlib: cryptodll.}
proc BN_get0_nist_prime_521*(): ptr BIGNUM {.cdecl, 
    importc: "BN_get0_nist_prime_521", dynlib: cryptodll.}
proc bn_expand2*(a: ptr BIGNUM; words: cint): ptr BIGNUM {.cdecl, 
    importc: "bn_expand2", dynlib: cryptodll.}
proc bn_dup_expand*(a: ptr BIGNUM; words: cint): ptr BIGNUM {.cdecl, 
    importc: "bn_dup_expand", dynlib: cryptodll.}
proc bn_mul_add_words*(rp: ptr culong; ap: ptr culong; num: cint; w: culong): culong {.
    cdecl, importc: "bn_mul_add_words", dynlib: cryptodll.}
proc bn_mul_words*(rp: ptr culong; ap: ptr culong; num: cint; w: culong): culong {.
    cdecl, importc: "bn_mul_words", dynlib: cryptodll.}
proc bn_sqr_words*(rp: ptr culong; ap: ptr culong; num: cint) {.cdecl, 
    importc: "bn_sqr_words", dynlib: cryptodll.}
proc bn_div_words*(h: culong; l: culong; d: culong): culong {.cdecl, 
    importc: "bn_div_words", dynlib: cryptodll.}
proc bn_add_words*(rp: ptr culong; ap: ptr culong; bp: ptr culong; num: cint): culong {.
    cdecl, importc: "bn_add_words", dynlib: cryptodll.}
proc bn_sub_words*(rp: ptr culong; ap: ptr culong; bp: ptr culong; num: cint): culong {.
    cdecl, importc: "bn_sub_words", dynlib: cryptodll.}
proc get_rfc2409_prime_768*(bn: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "get_rfc2409_prime_768", dynlib: cryptodll.}
proc get_rfc2409_prime_1024*(bn: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "get_rfc2409_prime_1024", dynlib: cryptodll.}
proc get_rfc3526_prime_1536*(bn: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "get_rfc3526_prime_1536", dynlib: cryptodll.}
proc get_rfc3526_prime_2048*(bn: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "get_rfc3526_prime_2048", dynlib: cryptodll.}
proc get_rfc3526_prime_3072*(bn: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "get_rfc3526_prime_3072", dynlib: cryptodll.}
proc get_rfc3526_prime_4096*(bn: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "get_rfc3526_prime_4096", dynlib: cryptodll.}
proc get_rfc3526_prime_6144*(bn: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "get_rfc3526_prime_6144", dynlib: cryptodll.}
proc get_rfc3526_prime_8192*(bn: ptr BIGNUM): ptr BIGNUM {.cdecl, 
    importc: "get_rfc3526_prime_8192", dynlib: cryptodll.}
proc BN_bntest_rand*(rnd: ptr BIGNUM; bits: cint; top: cint; bottom: cint): cint {.
    cdecl, importc: "BN_bntest_rand", dynlib: cryptodll.}
proc ERR_load_BN_strings*() {.cdecl, importc: "ERR_load_BN_strings", 
                              dynlib: cryptodll.}


proc d2i_ASN1_SEQUENCE_ANY*(a: ptr ptr ASN1_SEQUENCE_ANY; input: ptr ptr cuchar; 
                            len: clong): ptr ASN1_SEQUENCE_ANY {.cdecl, 
    importc: "d2i_ASN1_SEQUENCE_ANY", dynlib: cryptodll.}
proc i2d_ASN1_SEQUENCE_ANY*(a: ptr ASN1_SEQUENCE_ANY; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_SEQUENCE_ANY", dynlib: cryptodll.}
var ASN1_SEQUENCE_ANY_it* {.importc: "ASN1_SEQUENCE_ANY_it", dynlib: cryptodll.}: ASN1_ITEM

proc d2i_ASN1_SET_ANY*(a: ptr ptr ASN1_SEQUENCE_ANY; input: ptr ptr cuchar; 
                       len: clong): ptr ASN1_SEQUENCE_ANY {.cdecl, 
    importc: "d2i_ASN1_SET_ANY", dynlib: cryptodll.}
proc i2d_ASN1_SET_ANY*(a: ptr ASN1_SEQUENCE_ANY; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_SET_ANY", dynlib: cryptodll.}
var ASN1_SET_ANY_it* {.importc: "ASN1_SET_ANY_it", dynlib: cryptodll.}: ASN1_ITEM


proc ASN1_TYPE_new*(): ptr ASN1_TYPE {.cdecl, importc: "ASN1_TYPE_new", 
                                       dynlib: cryptodll.}
proc ASN1_TYPE_free*(a: ptr ASN1_TYPE) {.cdecl, importc: "ASN1_TYPE_free", 
    dynlib: cryptodll.}
proc d2i_ASN1_TYPE*(a: ptr ptr ASN1_TYPE; input: ptr ptr cuchar; len: clong): ptr ASN1_TYPE {.
    cdecl, importc: "d2i_ASN1_TYPE", dynlib: cryptodll.}
proc i2d_ASN1_TYPE*(a: ptr ASN1_TYPE; output: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_ASN1_TYPE", dynlib: cryptodll.}
var ASN1_ANY_it* {.importc: "ASN1_ANY_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_TYPE_get*(a: ptr ASN1_TYPE): cint {.cdecl, importc: "ASN1_TYPE_get", 
    dynlib: cryptodll.}
proc ASN1_TYPE_set*(a: ptr ASN1_TYPE; typ: cint; value: pointer) {.cdecl, 
    importc: "ASN1_TYPE_set", dynlib: cryptodll.}
proc ASN1_TYPE_set1*(a: ptr ASN1_TYPE; typ: cint; value: pointer): cint {.
    cdecl, importc: "ASN1_TYPE_set1", dynlib: cryptodll.}
proc ASN1_TYPE_cmp*(a: ptr ASN1_TYPE; b: ptr ASN1_TYPE): cint {.cdecl, 
    importc: "ASN1_TYPE_cmp", dynlib: cryptodll.}
proc ASN1_OBJECT_new*(): ptr ASN1_OBJECT {.cdecl, importc: "ASN1_OBJECT_new", 
    dynlib: cryptodll.}
proc ASN1_OBJECT_free*(a: ptr ASN1_OBJECT) {.cdecl, importc: "ASN1_OBJECT_free", 
    dynlib: cryptodll.}
proc i2d_ASN1_OBJECT*(a: ptr ASN1_OBJECT; pp: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_ASN1_OBJECT", dynlib: cryptodll.}
proc c2i_ASN1_OBJECT*(a: ptr ptr ASN1_OBJECT; pp: ptr ptr cuchar; length: clong): ptr ASN1_OBJECT {.
    cdecl, importc: "c2i_ASN1_OBJECT", dynlib: cryptodll.}
proc d2i_ASN1_OBJECT*(a: ptr ptr ASN1_OBJECT; pp: ptr ptr cuchar; length: clong): ptr ASN1_OBJECT {.
    cdecl, importc: "d2i_ASN1_OBJECT", dynlib: cryptodll.}
var ASN1_OBJECT_it* {.importc: "ASN1_OBJECT_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_STRING_new*(): ptr ASN1_STRING {.cdecl, importc: "ASN1_STRING_new", 
    dynlib: cryptodll.}
proc ASN1_STRING_free*(a: ptr ASN1_STRING) {.cdecl, importc: "ASN1_STRING_free", 
    dynlib: cryptodll.}
proc ASN1_STRING_copy*(dst: ptr ASN1_STRING; str: ptr ASN1_STRING): cint {.
    cdecl, importc: "ASN1_STRING_copy", dynlib: cryptodll.}
proc ASN1_STRING_dup*(a: ptr ASN1_STRING): ptr ASN1_STRING {.cdecl, 
    importc: "ASN1_STRING_dup", dynlib: cryptodll.}
proc ASN1_STRING_type_new*(typ: cint): ptr ASN1_STRING {.cdecl, 
    importc: "ASN1_STRING_type_new", dynlib: cryptodll.}
proc ASN1_STRING_cmp*(a: ptr ASN1_STRING; b: ptr ASN1_STRING): cint {.cdecl, 
    importc: "ASN1_STRING_cmp", dynlib: cryptodll.}
proc ASN1_STRING_set*(str: ptr ASN1_STRING; data: pointer; len: cint): cint {.
    cdecl, importc: "ASN1_STRING_set", dynlib: cryptodll.}
proc ASN1_STRING_set0*(str: ptr ASN1_STRING; data: pointer; len: cint) {.cdecl, 
    importc: "ASN1_STRING_set0", dynlib: cryptodll.}
proc ASN1_STRING_length*(x: ptr ASN1_STRING): cint {.cdecl, 
    importc: "ASN1_STRING_length", dynlib: cryptodll.}
proc ASN1_STRING_length_set*(x: ptr ASN1_STRING; n: cint) {.cdecl, 
    importc: "ASN1_STRING_length_set", dynlib: cryptodll.}
proc ASN1_STRING_type*(x: ptr ASN1_STRING): cint {.cdecl, 
    importc: "ASN1_STRING_type", dynlib: cryptodll.}
proc ASN1_STRING_data*(x: ptr ASN1_STRING): ptr cuchar {.cdecl, 
    importc: "ASN1_STRING_data", dynlib: cryptodll.}
proc ASN1_BIT_STRING_new*(): ptr ASN1_BIT_STRING {.cdecl, 
    importc: "ASN1_BIT_STRING_new", dynlib: cryptodll.}
proc ASN1_BIT_STRING_free*(a: ptr ASN1_BIT_STRING) {.cdecl, 
    importc: "ASN1_BIT_STRING_free", dynlib: cryptodll.}
proc d2i_ASN1_BIT_STRING*(a: ptr ptr ASN1_BIT_STRING; input: ptr ptr cuchar; 
                          len: clong): ptr ASN1_BIT_STRING {.cdecl, 
    importc: "d2i_ASN1_BIT_STRING", dynlib: cryptodll.}
proc i2d_ASN1_BIT_STRING*(a: ptr ASN1_BIT_STRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_BIT_STRING", dynlib: cryptodll.}
var ASN1_BIT_STRING_it* {.importc: "ASN1_BIT_STRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc i2c_ASN1_BIT_STRING*(a: ptr ASN1_BIT_STRING; pp: ptr ptr cuchar): cint {.
    cdecl, importc: "i2c_ASN1_BIT_STRING", dynlib: cryptodll.}
proc c2i_ASN1_BIT_STRING*(a: ptr ptr ASN1_BIT_STRING; pp: ptr ptr cuchar; 
                          length: clong): ptr ASN1_BIT_STRING {.cdecl, 
    importc: "c2i_ASN1_BIT_STRING", dynlib: cryptodll.}
proc ASN1_BIT_STRING_set*(a: ptr ASN1_BIT_STRING; d: ptr cuchar; length: cint): cint {.
    cdecl, importc: "ASN1_BIT_STRING_set", dynlib: cryptodll.}
proc ASN1_BIT_STRING_set_bit*(a: ptr ASN1_BIT_STRING; n: cint; value: cint): cint {.
    cdecl, importc: "ASN1_BIT_STRING_set_bit", dynlib: cryptodll.}
proc ASN1_BIT_STRING_get_bit*(a: ptr ASN1_BIT_STRING; n: cint): cint {.cdecl, 
    importc: "ASN1_BIT_STRING_get_bit", dynlib: cryptodll.}
proc ASN1_BIT_STRING_check*(a: ptr ASN1_BIT_STRING; flags: ptr cuchar; 
                            flags_len: cint): cint {.cdecl, 
    importc: "ASN1_BIT_STRING_check", dynlib: cryptodll.}
proc ASN1_BIT_STRING_name_print*(output: ptr BIO; bs: ptr ASN1_BIT_STRING; 
                                 tbl: ptr BIT_STRING_BITNAME; indent: cint): cint {.
    cdecl, importc: "ASN1_BIT_STRING_name_print", dynlib: cryptodll.}
proc ASN1_BIT_STRING_num_asc*(name: cstring; tbl: ptr BIT_STRING_BITNAME): cint {.
    cdecl, importc: "ASN1_BIT_STRING_num_asc", dynlib: cryptodll.}
proc ASN1_BIT_STRING_set_asc*(bs: ptr ASN1_BIT_STRING; name: cstring; 
                              value: cint; tbl: ptr BIT_STRING_BITNAME): cint {.
    cdecl, importc: "ASN1_BIT_STRING_set_asc", dynlib: cryptodll.}
proc i2d_ASN1_BOOLEAN*(a: cint; pp: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_ASN1_BOOLEAN", dynlib: cryptodll.}
proc d2i_ASN1_BOOLEAN*(a: ptr cint; pp: ptr ptr cuchar; length: clong): cint {.
    cdecl, importc: "d2i_ASN1_BOOLEAN", dynlib: cryptodll.}
proc ASN1_INTEGER_new*(): ptr ASN1_INTEGER {.cdecl, importc: "ASN1_INTEGER_new", 
    dynlib: cryptodll.}
proc ASN1_INTEGER_free*(a: ptr ASN1_INTEGER) {.cdecl, 
    importc: "ASN1_INTEGER_free", dynlib: cryptodll.}
proc d2i_ASN1_INTEGER*(a: ptr ptr ASN1_INTEGER; input: ptr ptr cuchar; len: clong): ptr ASN1_INTEGER {.
    cdecl, importc: "d2i_ASN1_INTEGER", dynlib: cryptodll.}
proc i2d_ASN1_INTEGER*(a: ptr ASN1_INTEGER; output: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_ASN1_INTEGER", dynlib: cryptodll.}
var ASN1_INTEGER_it* {.importc: "ASN1_INTEGER_it", dynlib: cryptodll.}: ASN1_ITEM

proc i2c_ASN1_INTEGER*(a: ptr ASN1_INTEGER; pp: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2c_ASN1_INTEGER", dynlib: cryptodll.}
proc c2i_ASN1_INTEGER*(a: ptr ptr ASN1_INTEGER; pp: ptr ptr cuchar; 
                       length: clong): ptr ASN1_INTEGER {.cdecl, 
    importc: "c2i_ASN1_INTEGER", dynlib: cryptodll.}
proc d2i_ASN1_UINTEGER*(a: ptr ptr ASN1_INTEGER; pp: ptr ptr cuchar; 
                        length: clong): ptr ASN1_INTEGER {.cdecl, 
    importc: "d2i_ASN1_UINTEGER", dynlib: cryptodll.}
proc ASN1_INTEGER_dup*(x: ptr ASN1_INTEGER): ptr ASN1_INTEGER {.cdecl, 
    importc: "ASN1_INTEGER_dup", dynlib: cryptodll.}
proc ASN1_INTEGER_cmp*(x: ptr ASN1_INTEGER; y: ptr ASN1_INTEGER): cint {.cdecl, 
    importc: "ASN1_INTEGER_cmp", dynlib: cryptodll.}
proc ASN1_ENUMERATED_new*(): ptr ASN1_ENUMERATED {.cdecl, 
    importc: "ASN1_ENUMERATED_new", dynlib: cryptodll.}
proc ASN1_ENUMERATED_free*(a: ptr ASN1_ENUMERATED) {.cdecl, 
    importc: "ASN1_ENUMERATED_free", dynlib: cryptodll.}
proc d2i_ASN1_ENUMERATED*(a: ptr ptr ASN1_ENUMERATED; input: ptr ptr cuchar; 
                          len: clong): ptr ASN1_ENUMERATED {.cdecl, 
    importc: "d2i_ASN1_ENUMERATED", dynlib: cryptodll.}
proc i2d_ASN1_ENUMERATED*(a: ptr ASN1_ENUMERATED; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_ENUMERATED", dynlib: cryptodll.}
var ASN1_ENUMERATED_it* {.importc: "ASN1_ENUMERATED_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_UTCTIME_check*(a: ptr ASN1_UTCTIME): cint {.cdecl, 
    importc: "ASN1_UTCTIME_check", dynlib: cryptodll.}
proc ASN1_UTCTIME_set*(s: ptr ASN1_UTCTIME; t: time_t): ptr ASN1_UTCTIME {.
    cdecl, importc: "ASN1_UTCTIME_set", dynlib: cryptodll.}
proc ASN1_UTCTIME_adj*(s: ptr ASN1_UTCTIME; t: time_t; offset_day: cint; 
                       offset_sec: clong): ptr ASN1_UTCTIME {.cdecl, 
    importc: "ASN1_UTCTIME_adj", dynlib: cryptodll.}
proc ASN1_UTCTIME_set_string*(s: ptr ASN1_UTCTIME; str: cstring): cint {.cdecl, 
    importc: "ASN1_UTCTIME_set_string", dynlib: cryptodll.}
proc ASN1_UTCTIME_cmp_time_t*(s: ptr ASN1_UTCTIME; t: time_t): cint {.cdecl, 
    importc: "ASN1_UTCTIME_cmp_time_t", dynlib: cryptodll.}
proc ASN1_GENERALIZEDTIME_check*(a: ptr ASN1_GENERALIZEDTIME): cint {.cdecl, 
    importc: "ASN1_GENERALIZEDTIME_check", dynlib: cryptodll.}
proc ASN1_GENERALIZEDTIME_set*(s: ptr ASN1_GENERALIZEDTIME; t: time_t): ptr ASN1_GENERALIZEDTIME {.
    cdecl, importc: "ASN1_GENERALIZEDTIME_set", dynlib: cryptodll.}
proc ASN1_GENERALIZEDTIME_adj*(s: ptr ASN1_GENERALIZEDTIME; t: time_t; 
                               offset_day: cint; offset_sec: clong): ptr ASN1_GENERALIZEDTIME {.
    cdecl, importc: "ASN1_GENERALIZEDTIME_adj", dynlib: cryptodll.}
proc ASN1_GENERALIZEDTIME_set_string*(s: ptr ASN1_GENERALIZEDTIME; str: cstring): cint {.
    cdecl, importc: "ASN1_GENERALIZEDTIME_set_string", dynlib: cryptodll.}
proc ASN1_OCTET_STRING_new*(): ptr ASN1_OCTET_STRING {.cdecl, 
    importc: "ASN1_OCTET_STRING_new", dynlib: cryptodll.}
proc ASN1_OCTET_STRING_free*(a: ptr ASN1_OCTET_STRING) {.cdecl, 
    importc: "ASN1_OCTET_STRING_free", dynlib: cryptodll.}
proc d2i_ASN1_OCTET_STRING*(a: ptr ptr ASN1_OCTET_STRING; input: ptr ptr cuchar; 
                            len: clong): ptr ASN1_OCTET_STRING {.cdecl, 
    importc: "d2i_ASN1_OCTET_STRING", dynlib: cryptodll.}
proc i2d_ASN1_OCTET_STRING*(a: ptr ASN1_OCTET_STRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_OCTET_STRING", dynlib: cryptodll.}
var ASN1_OCTET_STRING_it* {.importc: "ASN1_OCTET_STRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_OCTET_STRING_dup*(a: ptr ASN1_OCTET_STRING): ptr ASN1_OCTET_STRING {.
    cdecl, importc: "ASN1_OCTET_STRING_dup", dynlib: cryptodll.}
proc ASN1_OCTET_STRING_cmp*(a: ptr ASN1_OCTET_STRING; b: ptr ASN1_OCTET_STRING): cint {.
    cdecl, importc: "ASN1_OCTET_STRING_cmp", dynlib: cryptodll.}
proc ASN1_OCTET_STRING_set*(str: ptr ASN1_OCTET_STRING; data: ptr cuchar; 
                            len: cint): cint {.cdecl, 
    importc: "ASN1_OCTET_STRING_set", dynlib: cryptodll.}
proc ASN1_VISIBLESTRING_new*(): ptr ASN1_VISIBLESTRING {.cdecl, 
    importc: "ASN1_VISIBLESTRING_new", dynlib: cryptodll.}
proc ASN1_VISIBLESTRING_free*(a: ptr ASN1_VISIBLESTRING) {.cdecl, 
    importc: "ASN1_VISIBLESTRING_free", dynlib: cryptodll.}
proc d2i_ASN1_VISIBLESTRING*(a: ptr ptr ASN1_VISIBLESTRING; input: ptr ptr cuchar; 
                             len: clong): ptr ASN1_VISIBLESTRING {.cdecl, 
    importc: "d2i_ASN1_VISIBLESTRING", dynlib: cryptodll.}
proc i2d_ASN1_VISIBLESTRING*(a: ptr ASN1_VISIBLESTRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_VISIBLESTRING", dynlib: cryptodll.}
var ASN1_VISIBLESTRING_it* {.importc: "ASN1_VISIBLESTRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_UNIVERSALSTRING_new*(): ptr ASN1_UNIVERSALSTRING {.cdecl, 
    importc: "ASN1_UNIVERSALSTRING_new", dynlib: cryptodll.}
proc ASN1_UNIVERSALSTRING_free*(a: ptr ASN1_UNIVERSALSTRING) {.cdecl, 
    importc: "ASN1_UNIVERSALSTRING_free", dynlib: cryptodll.}
proc d2i_ASN1_UNIVERSALSTRING*(a: ptr ptr ASN1_UNIVERSALSTRING; 
                               input: ptr ptr cuchar; len: clong): ptr ASN1_UNIVERSALSTRING {.
    cdecl, importc: "d2i_ASN1_UNIVERSALSTRING", dynlib: cryptodll.}
proc i2d_ASN1_UNIVERSALSTRING*(a: ptr ASN1_UNIVERSALSTRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_UNIVERSALSTRING", dynlib: cryptodll.}
var ASN1_UNIVERSALSTRING_it* {.importc: "ASN1_UNIVERSALSTRING_it", 
                               dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_UTF8STRING_new*(): ptr ASN1_UTF8STRING {.cdecl, 
    importc: "ASN1_UTF8STRING_new", dynlib: cryptodll.}
proc ASN1_UTF8STRING_free*(a: ptr ASN1_UTF8STRING) {.cdecl, 
    importc: "ASN1_UTF8STRING_free", dynlib: cryptodll.}
proc d2i_ASN1_UTF8STRING*(a: ptr ptr ASN1_UTF8STRING; input: ptr ptr cuchar; 
                          len: clong): ptr ASN1_UTF8STRING {.cdecl, 
    importc: "d2i_ASN1_UTF8STRING", dynlib: cryptodll.}
proc i2d_ASN1_UTF8STRING*(a: ptr ASN1_UTF8STRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_UTF8STRING", dynlib: cryptodll.}
var ASN1_UTF8STRING_it* {.importc: "ASN1_UTF8STRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_NULL_new*(): ptr ASN1_NULL {.cdecl, importc: "ASN1_NULL_new", 
                                       dynlib: cryptodll.}
proc ASN1_NULL_free*(a: ptr ASN1_NULL) {.cdecl, importc: "ASN1_NULL_free", 
    dynlib: cryptodll.}
proc d2i_ASN1_NULL*(a: ptr ptr ASN1_NULL; input: ptr ptr cuchar; len: clong): ptr ASN1_NULL {.
    cdecl, importc: "d2i_ASN1_NULL", dynlib: cryptodll.}
proc i2d_ASN1_NULL*(a: ptr ASN1_NULL; output: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_ASN1_NULL", dynlib: cryptodll.}
var ASN1_NULL_it* {.importc: "ASN1_NULL_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_BMPSTRING_new*(): ptr ASN1_BMPSTRING {.cdecl, 
    importc: "ASN1_BMPSTRING_new", dynlib: cryptodll.}
proc ASN1_BMPSTRING_free*(a: ptr ASN1_BMPSTRING) {.cdecl, 
    importc: "ASN1_BMPSTRING_free", dynlib: cryptodll.}
proc d2i_ASN1_BMPSTRING*(a: ptr ptr ASN1_BMPSTRING; input: ptr ptr cuchar; 
                         len: clong): ptr ASN1_BMPSTRING {.cdecl, 
    importc: "d2i_ASN1_BMPSTRING", dynlib: cryptodll.}
proc i2d_ASN1_BMPSTRING*(a: ptr ASN1_BMPSTRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_BMPSTRING", dynlib: cryptodll.}
var ASN1_BMPSTRING_it* {.importc: "ASN1_BMPSTRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc UTF8_getc*(str: ptr cuchar; len: cint; val: ptr culong): cint {.cdecl, 
    importc: "UTF8_getc", dynlib: cryptodll.}
proc UTF8_putc*(str: ptr cuchar; len: cint; value: culong): cint {.cdecl, 
    importc: "UTF8_putc", dynlib: cryptodll.}
proc ASN1_PRINTABLE_new*(): ptr ASN1_STRING {.cdecl, 
    importc: "ASN1_PRINTABLE_new", dynlib: cryptodll.}
proc ASN1_PRINTABLE_free*(a: ptr ASN1_STRING) {.cdecl, 
    importc: "ASN1_PRINTABLE_free", dynlib: cryptodll.}
proc d2i_ASN1_PRINTABLE*(a: ptr ptr ASN1_STRING; input: ptr ptr cuchar; len: clong): ptr ASN1_STRING {.
    cdecl, importc: "d2i_ASN1_PRINTABLE", dynlib: cryptodll.}
proc i2d_ASN1_PRINTABLE*(a: ptr ASN1_STRING; output: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_ASN1_PRINTABLE", dynlib: cryptodll.}
var ASN1_PRINTABLE_it* {.importc: "ASN1_PRINTABLE_it", dynlib: cryptodll.}: ASN1_ITEM

proc DIRECTORYSTRING_new*(): ptr ASN1_STRING {.cdecl, 
    importc: "DIRECTORYSTRING_new", dynlib: cryptodll.}
proc DIRECTORYSTRING_free*(a: ptr ASN1_STRING) {.cdecl, 
    importc: "DIRECTORYSTRING_free", dynlib: cryptodll.}
proc d2i_DIRECTORYSTRING*(a: ptr ptr ASN1_STRING; input: ptr ptr cuchar; len: clong): ptr ASN1_STRING {.
    cdecl, importc: "d2i_DIRECTORYSTRING", dynlib: cryptodll.}
proc i2d_DIRECTORYSTRING*(a: ptr ASN1_STRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_DIRECTORYSTRING", dynlib: cryptodll.}
var DIRECTORYSTRING_it* {.importc: "DIRECTORYSTRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc DISPLAYTEXT_new*(): ptr ASN1_STRING {.cdecl, importc: "DISPLAYTEXT_new", 
    dynlib: cryptodll.}
proc DISPLAYTEXT_free*(a: ptr ASN1_STRING) {.cdecl, importc: "DISPLAYTEXT_free", 
    dynlib: cryptodll.}
proc d2i_DISPLAYTEXT*(a: ptr ptr ASN1_STRING; input: ptr ptr cuchar; len: clong): ptr ASN1_STRING {.
    cdecl, importc: "d2i_DISPLAYTEXT", dynlib: cryptodll.}
proc i2d_DISPLAYTEXT*(a: ptr ASN1_STRING; output: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_DISPLAYTEXT", dynlib: cryptodll.}
var DISPLAYTEXT_it* {.importc: "DISPLAYTEXT_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_PRINTABLESTRING_new*(): ptr ASN1_PRINTABLESTRING {.cdecl, 
    importc: "ASN1_PRINTABLESTRING_new", dynlib: cryptodll.}
proc ASN1_PRINTABLESTRING_free*(a: ptr ASN1_PRINTABLESTRING) {.cdecl, 
    importc: "ASN1_PRINTABLESTRING_free", dynlib: cryptodll.}
proc d2i_ASN1_PRINTABLESTRING*(a: ptr ptr ASN1_PRINTABLESTRING; 
                               input: ptr ptr cuchar; len: clong): ptr ASN1_PRINTABLESTRING {.
    cdecl, importc: "d2i_ASN1_PRINTABLESTRING", dynlib: cryptodll.}
proc i2d_ASN1_PRINTABLESTRING*(a: ptr ASN1_PRINTABLESTRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_PRINTABLESTRING", dynlib: cryptodll.}
var ASN1_PRINTABLESTRING_it* {.importc: "ASN1_PRINTABLESTRING_it", 
                               dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_T61STRING_new*(): ptr ASN1_T61STRING {.cdecl, 
    importc: "ASN1_T61STRING_new", dynlib: cryptodll.}
proc ASN1_T61STRING_free*(a: ptr ASN1_T61STRING) {.cdecl, 
    importc: "ASN1_T61STRING_free", dynlib: cryptodll.}
proc d2i_ASN1_T61STRING*(a: ptr ptr ASN1_T61STRING; input: ptr ptr cuchar; 
                         len: clong): ptr ASN1_T61STRING {.cdecl, 
    importc: "d2i_ASN1_T61STRING", dynlib: cryptodll.}
proc i2d_ASN1_T61STRING*(a: ptr ASN1_T61STRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_T61STRING", dynlib: cryptodll.}
var ASN1_T61STRING_it* {.importc: "ASN1_T61STRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_IA5STRING_new*(): ptr ASN1_IA5STRING {.cdecl, 
    importc: "ASN1_IA5STRING_new", dynlib: cryptodll.}
proc ASN1_IA5STRING_free*(a: ptr ASN1_IA5STRING) {.cdecl, 
    importc: "ASN1_IA5STRING_free", dynlib: cryptodll.}
proc d2i_ASN1_IA5STRING*(a: ptr ptr ASN1_IA5STRING; input: ptr ptr cuchar; 
                         len: clong): ptr ASN1_IA5STRING {.cdecl, 
    importc: "d2i_ASN1_IA5STRING", dynlib: cryptodll.}
proc i2d_ASN1_IA5STRING*(a: ptr ASN1_IA5STRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_IA5STRING", dynlib: cryptodll.}
var ASN1_IA5STRING_it* {.importc: "ASN1_IA5STRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_GENERALSTRING_new*(): ptr ASN1_GENERALSTRING {.cdecl, 
    importc: "ASN1_GENERALSTRING_new", dynlib: cryptodll.}
proc ASN1_GENERALSTRING_free*(a: ptr ASN1_GENERALSTRING) {.cdecl, 
    importc: "ASN1_GENERALSTRING_free", dynlib: cryptodll.}
proc d2i_ASN1_GENERALSTRING*(a: ptr ptr ASN1_GENERALSTRING; input: ptr ptr cuchar; 
                             len: clong): ptr ASN1_GENERALSTRING {.cdecl, 
    importc: "d2i_ASN1_GENERALSTRING", dynlib: cryptodll.}
proc i2d_ASN1_GENERALSTRING*(a: ptr ASN1_GENERALSTRING; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_GENERALSTRING", dynlib: cryptodll.}
var ASN1_GENERALSTRING_it* {.importc: "ASN1_GENERALSTRING_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_UTCTIME_new*(): ptr ASN1_UTCTIME {.cdecl, importc: "ASN1_UTCTIME_new", 
    dynlib: cryptodll.}
proc ASN1_UTCTIME_free*(a: ptr ASN1_UTCTIME) {.cdecl, 
    importc: "ASN1_UTCTIME_free", dynlib: cryptodll.}
proc d2i_ASN1_UTCTIME*(a: ptr ptr ASN1_UTCTIME; input: ptr ptr cuchar; len: clong): ptr ASN1_UTCTIME {.
    cdecl, importc: "d2i_ASN1_UTCTIME", dynlib: cryptodll.}
proc i2d_ASN1_UTCTIME*(a: ptr ASN1_UTCTIME; output: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_ASN1_UTCTIME", dynlib: cryptodll.}
var ASN1_UTCTIME_it* {.importc: "ASN1_UTCTIME_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_GENERALIZEDTIME_new*(): ptr ASN1_GENERALIZEDTIME {.cdecl, 
    importc: "ASN1_GENERALIZEDTIME_new", dynlib: cryptodll.}
proc ASN1_GENERALIZEDTIME_free*(a: ptr ASN1_GENERALIZEDTIME) {.cdecl, 
    importc: "ASN1_GENERALIZEDTIME_free", dynlib: cryptodll.}
proc d2i_ASN1_GENERALIZEDTIME*(a: ptr ptr ASN1_GENERALIZEDTIME; 
                               input: ptr ptr cuchar; len: clong): ptr ASN1_GENERALIZEDTIME {.
    cdecl, importc: "d2i_ASN1_GENERALIZEDTIME", dynlib: cryptodll.}
proc i2d_ASN1_GENERALIZEDTIME*(a: ptr ASN1_GENERALIZEDTIME; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_ASN1_GENERALIZEDTIME", dynlib: cryptodll.}
var ASN1_GENERALIZEDTIME_it* {.importc: "ASN1_GENERALIZEDTIME_it", 
                               dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_TIME_new*(): ptr ASN1_TIME {.cdecl, importc: "ASN1_TIME_new", 
                                       dynlib: cryptodll.}
proc ASN1_TIME_free*(a: ptr ASN1_TIME) {.cdecl, importc: "ASN1_TIME_free", 
    dynlib: cryptodll.}
proc d2i_ASN1_TIME*(a: ptr ptr ASN1_TIME; input: ptr ptr cuchar; len: clong): ptr ASN1_TIME {.
    cdecl, importc: "d2i_ASN1_TIME", dynlib: cryptodll.}
proc i2d_ASN1_TIME*(a: ptr ASN1_TIME; output: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_ASN1_TIME", dynlib: cryptodll.}
var ASN1_TIME_it* {.importc: "ASN1_TIME_it", dynlib: cryptodll.}: ASN1_ITEM

var ASN1_OCTET_STRING_NDEF_it* {.importc: "ASN1_OCTET_STRING_NDEF_it", 
                                 dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_TIME_set*(s: ptr ASN1_TIME; t: time_t): ptr ASN1_TIME {.cdecl, 
    importc: "ASN1_TIME_set", dynlib: cryptodll.}
proc ASN1_TIME_adj*(s: ptr ASN1_TIME; t: time_t; offset_day: cint; 
                    offset_sec: clong): ptr ASN1_TIME {.cdecl, 
    importc: "ASN1_TIME_adj", dynlib: cryptodll.}
proc ASN1_TIME_check*(t: ptr ASN1_TIME): cint {.cdecl, 
    importc: "ASN1_TIME_check", dynlib: cryptodll.}
proc ASN1_TIME_to_generalizedtime*(t: ptr ASN1_TIME; 
                                   output: ptr ptr ASN1_GENERALIZEDTIME): ptr ASN1_GENERALIZEDTIME {.
    cdecl, importc: "ASN1_TIME_to_generalizedtime", dynlib: cryptodll.}
proc ASN1_TIME_set_string*(s: ptr ASN1_TIME; str: cstring): cint {.cdecl, 
    importc: "ASN1_TIME_set_string", dynlib: cryptodll.}
proc i2d_ASN1_SET*(a: ptr stack_st_OPENSSL_BLOCK; pp: ptr ptr cuchar; 
                   i2d: ptr i2d_of_void; ex_tag: cint; ex_class: cint; 
                   is_set: cint): cint {.cdecl, importc: "i2d_ASN1_SET", 
    dynlib: cryptodll.}
proc d2i_ASN1_SET*(a: ptr ptr stack_st_OPENSSL_BLOCK; pp: ptr ptr cuchar; 
                   length: clong; d2i: ptr d2i_of_void; 
                   free_func: proc (a2: OPENSSL_BLOCK) {.cdecl.}; ex_tag: cint; 
                   ex_class: cint): ptr stack_st_OPENSSL_BLOCK {.cdecl, 
    importc: "d2i_ASN1_SET", dynlib: cryptodll.}
proc i2a_ASN1_INTEGER*(bp: ptr BIO; a: ptr ASN1_INTEGER): cint {.cdecl, 
    importc: "i2a_ASN1_INTEGER", dynlib: cryptodll.}
proc a2i_ASN1_INTEGER*(bp: ptr BIO; bs: ptr ASN1_INTEGER; buf: cstring; 
                       size: cint): cint {.cdecl, importc: "a2i_ASN1_INTEGER", 
    dynlib: cryptodll.}
proc i2a_ASN1_ENUMERATED*(bp: ptr BIO; a: ptr ASN1_ENUMERATED): cint {.cdecl, 
    importc: "i2a_ASN1_ENUMERATED", dynlib: cryptodll.}
proc a2i_ASN1_ENUMERATED*(bp: ptr BIO; bs: ptr ASN1_ENUMERATED; buf: cstring; 
                          size: cint): cint {.cdecl, 
    importc: "a2i_ASN1_ENUMERATED", dynlib: cryptodll.}
proc i2a_ASN1_OBJECT*(bp: ptr BIO; a: ptr ASN1_OBJECT): cint {.cdecl, 
    importc: "i2a_ASN1_OBJECT", dynlib: cryptodll.}
proc a2i_ASN1_STRING*(bp: ptr BIO; bs: ptr ASN1_STRING; buf: cstring; size: cint): cint {.
    cdecl, importc: "a2i_ASN1_STRING", dynlib: cryptodll.}
proc i2a_ASN1_STRING*(bp: ptr BIO; a: ptr ASN1_STRING; typ: cint): cint {.
    cdecl, importc: "i2a_ASN1_STRING", dynlib: cryptodll.}
proc i2t_ASN1_OBJECT*(buf: cstring; buf_len: cint; a: ptr ASN1_OBJECT): cint {.
    cdecl, importc: "i2t_ASN1_OBJECT", dynlib: cryptodll.}
proc a2d_ASN1_OBJECT*(output: ptr cuchar; olen: cint; buf: cstring; num: cint): cint {.
    cdecl, importc: "a2d_ASN1_OBJECT", dynlib: cryptodll.}
proc ASN1_OBJECT_create*(nid: cint; data: ptr cuchar; len: cint; sn: cstring; 
                         ln: cstring): ptr ASN1_OBJECT {.cdecl, 
    importc: "ASN1_OBJECT_create", dynlib: cryptodll.}
proc ASN1_INTEGER_set*(a: ptr ASN1_INTEGER; v: clong): cint {.cdecl, 
    importc: "ASN1_INTEGER_set", dynlib: cryptodll.}
proc ASN1_INTEGER_get*(a: ptr ASN1_INTEGER): clong {.cdecl, 
    importc: "ASN1_INTEGER_get", dynlib: cryptodll.}
proc BN_to_ASN1_INTEGER*(bn: ptr BIGNUM; ai: ptr ASN1_INTEGER): ptr ASN1_INTEGER {.
    cdecl, importc: "BN_to_ASN1_INTEGER", dynlib: cryptodll.}
proc ASN1_INTEGER_to_BN*(ai: ptr ASN1_INTEGER; bn: ptr BIGNUM): ptr BIGNUM {.
    cdecl, importc: "ASN1_INTEGER_to_BN", dynlib: cryptodll.}
proc ASN1_ENUMERATED_set*(a: ptr ASN1_ENUMERATED; v: clong): cint {.cdecl, 
    importc: "ASN1_ENUMERATED_set", dynlib: cryptodll.}
proc ASN1_ENUMERATED_get*(a: ptr ASN1_ENUMERATED): clong {.cdecl, 
    importc: "ASN1_ENUMERATED_get", dynlib: cryptodll.}
proc BN_to_ASN1_ENUMERATED*(bn: ptr BIGNUM; ai: ptr ASN1_ENUMERATED): ptr ASN1_ENUMERATED {.
    cdecl, importc: "BN_to_ASN1_ENUMERATED", dynlib: cryptodll.}
proc ASN1_ENUMERATED_to_BN*(ai: ptr ASN1_ENUMERATED; bn: ptr BIGNUM): ptr BIGNUM {.
    cdecl, importc: "ASN1_ENUMERATED_to_BN", dynlib: cryptodll.}
proc ASN1_PRINTABLE_type*(s: ptr cuchar; max: cint): cint {.cdecl, 
    importc: "ASN1_PRINTABLE_type", dynlib: cryptodll.}
proc i2d_ASN1_bytes*(a: ptr ASN1_STRING; pp: ptr ptr cuchar; tag: cint; 
                     xclass: cint): cint {.cdecl, importc: "i2d_ASN1_bytes", 
    dynlib: cryptodll.}
proc d2i_ASN1_bytes*(a: ptr ptr ASN1_STRING; pp: ptr ptr cuchar; length: clong; 
                     Ptag: cint; Pclass: cint): ptr ASN1_STRING {.cdecl, 
    importc: "d2i_ASN1_bytes", dynlib: cryptodll.}
proc ASN1_tag2bit*(tag: cint): culong {.cdecl, importc: "ASN1_tag2bit", 
                                        dynlib: cryptodll.}
proc d2i_ASN1_type_bytes*(a: ptr ptr ASN1_STRING; pp: ptr ptr cuchar; 
                          length: clong; typ: cint): ptr ASN1_STRING {.cdecl, 
    importc: "d2i_ASN1_type_bytes", dynlib: cryptodll.}
proc asn1_Finish*(c: ptr ASN1_CTX): cint {.cdecl, importc: "asn1_Finish", 
    dynlib: cryptodll.}
proc asn1_const_Finish*(c: ptr ASN1_const_CTX): cint {.cdecl, 
    importc: "asn1_const_Finish", dynlib: cryptodll.}
proc ASN1_get_object*(pp: ptr ptr cuchar; plength: ptr clong; ptag: ptr cint; 
                      pclass: ptr cint; omax: clong): cint {.cdecl, 
    importc: "ASN1_get_object", dynlib: cryptodll.}
proc ASN1_check_infinite_end*(p: ptr ptr cuchar; len: clong): cint {.cdecl, 
    importc: "ASN1_check_infinite_end", dynlib: cryptodll.}
proc ASN1_const_check_infinite_end*(p: ptr ptr cuchar; len: clong): cint {.
    cdecl, importc: "ASN1_const_check_infinite_end", dynlib: cryptodll.}
proc ASN1_put_object*(pp: ptr ptr cuchar; constructed: cint; length: cint; 
                      tag: cint; xclass: cint) {.cdecl, 
    importc: "ASN1_put_object", dynlib: cryptodll.}
proc ASN1_put_eoc*(pp: ptr ptr cuchar): cint {.cdecl, importc: "ASN1_put_eoc", 
    dynlib: cryptodll.}
proc ASN1_object_size*(constructed: cint; length: cint; tag: cint): cint {.
    cdecl, importc: "ASN1_object_size", dynlib: cryptodll.}
proc ASN1_dup*(i2d: ptr i2d_of_void; d2i: ptr d2i_of_void; x: pointer): pointer {.
    cdecl, importc: "ASN1_dup", dynlib: cryptodll.}
proc ASN1_item_dup*(it: ptr ASN1_ITEM; x: pointer): pointer {.cdecl, 
    importc: "ASN1_item_dup", dynlib: cryptodll.}
proc ASN1_d2i_fp*(xnew: proc (): pointer {.cdecl.}; d2i: ptr d2i_of_void; 
                  input: ptr FILE; x: ptr pointer): pointer {.cdecl, 
    importc: "ASN1_d2i_fp", dynlib: cryptodll.}
proc ASN1_item_d2i_fp*(it: ptr ASN1_ITEM; input: ptr FILE; x: pointer): pointer {.
    cdecl, importc: "ASN1_item_d2i_fp", dynlib: cryptodll.}
proc ASN1_i2d_fp*(i2d: ptr i2d_of_void; output: ptr FILE; x: pointer): cint {.
    cdecl, importc: "ASN1_i2d_fp", dynlib: cryptodll.}
proc ASN1_item_i2d_fp*(it: ptr ASN1_ITEM; output: ptr FILE; x: pointer): cint {.
    cdecl, importc: "ASN1_item_i2d_fp", dynlib: cryptodll.}
proc ASN1_STRING_print_ex_fp*(fp: ptr FILE; str: ptr ASN1_STRING; flags: culong): cint {.
    cdecl, importc: "ASN1_STRING_print_ex_fp", dynlib: cryptodll.}
proc ASN1_STRING_to_UTF8*(output: ptr ptr cuchar; input: ptr ASN1_STRING): cint {.
    cdecl, importc: "ASN1_STRING_to_UTF8", dynlib: cryptodll.}
proc ASN1_d2i_bio*(xnew: proc (): pointer {.cdecl.}; d2i: ptr d2i_of_void; 
                   input: ptr BIO; x: ptr pointer): pointer {.cdecl, 
    importc: "ASN1_d2i_bio", dynlib: cryptodll.}
proc ASN1_item_d2i_bio*(it: ptr ASN1_ITEM; input: ptr BIO; x: pointer): pointer {.
    cdecl, importc: "ASN1_item_d2i_bio", dynlib: cryptodll.}
proc ASN1_i2d_bio*(i2d: ptr i2d_of_void; output: ptr BIO; x: ptr cuchar): cint {.
    cdecl, importc: "ASN1_i2d_bio", dynlib: cryptodll.}
proc ASN1_item_i2d_bio*(it: ptr ASN1_ITEM; output: ptr BIO; x: pointer): cint {.
    cdecl, importc: "ASN1_item_i2d_bio", dynlib: cryptodll.}
proc ASN1_UTCTIME_print*(fp: ptr BIO; a: ptr ASN1_UTCTIME): cint {.cdecl, 
    importc: "ASN1_UTCTIME_print", dynlib: cryptodll.}
proc ASN1_GENERALIZEDTIME_print*(fp: ptr BIO; a: ptr ASN1_GENERALIZEDTIME): cint {.
    cdecl, importc: "ASN1_GENERALIZEDTIME_print", dynlib: cryptodll.}
proc ASN1_TIME_print*(fp: ptr BIO; a: ptr ASN1_TIME): cint {.cdecl, 
    importc: "ASN1_TIME_print", dynlib: cryptodll.}
proc ASN1_STRING_print*(bp: ptr BIO; v: ptr ASN1_STRING): cint {.cdecl, 
    importc: "ASN1_STRING_print", dynlib: cryptodll.}
proc ASN1_STRING_print_ex*(output: ptr BIO; str: ptr ASN1_STRING; flags: culong): cint {.
    cdecl, importc: "ASN1_STRING_print_ex", dynlib: cryptodll.}
proc ASN1_bn_print*(bp: ptr BIO; number: cstring; num: ptr BIGNUM; 
                    buf: ptr cuchar; off: cint): cint {.cdecl, 
    importc: "ASN1_bn_print", dynlib: cryptodll.}
proc ASN1_parse*(bp: ptr BIO; pp: ptr cuchar; len: clong; indent: cint): cint {.
    cdecl, importc: "ASN1_parse", dynlib: cryptodll.}
proc ASN1_parse_dump*(bp: ptr BIO; pp: ptr cuchar; len: clong; indent: cint; 
                      dump: cint): cint {.cdecl, importc: "ASN1_parse_dump", 
    dynlib: cryptodll.}
proc ASN1_tag2str*(tag: cint): cstring {.cdecl, importc: "ASN1_tag2str", 
    dynlib: cryptodll.}
proc NETSCAPE_X509_new*(): ptr NETSCAPE_X509 {.cdecl, 
    importc: "NETSCAPE_X509_new", dynlib: cryptodll.}
proc NETSCAPE_X509_free*(a: ptr NETSCAPE_X509) {.cdecl, 
    importc: "NETSCAPE_X509_free", dynlib: cryptodll.}
proc d2i_NETSCAPE_X509*(a: ptr ptr NETSCAPE_X509; input: ptr ptr cuchar; len: clong): ptr NETSCAPE_X509 {.
    cdecl, importc: "d2i_NETSCAPE_X509", dynlib: cryptodll.}
proc i2d_NETSCAPE_X509*(a: ptr NETSCAPE_X509; output: ptr ptr cuchar): cint {.
    cdecl, importc: "i2d_NETSCAPE_X509", dynlib: cryptodll.}
var NETSCAPE_X509_it* {.importc: "NETSCAPE_X509_it", dynlib: cryptodll.}: ASN1_ITEM

proc ASN1_UNIVERSALSTRING_to_string*(s: ptr ASN1_UNIVERSALSTRING): cint {.cdecl, 
    importc: "ASN1_UNIVERSALSTRING_to_string", dynlib: cryptodll.}
proc ASN1_TYPE_set_octetstring*(a: ptr ASN1_TYPE; data: ptr cuchar; len: cint): cint {.
    cdecl, importc: "ASN1_TYPE_set_octetstring", dynlib: cryptodll.}
proc ASN1_TYPE_get_octetstring*(a: ptr ASN1_TYPE; data: ptr cuchar; 
                                max_len: cint): cint {.cdecl, 
    importc: "ASN1_TYPE_get_octetstring", dynlib: cryptodll.}
proc ASN1_TYPE_set_int_octetstring*(a: ptr ASN1_TYPE; num: clong; 
                                    data: ptr cuchar; len: cint): cint {.cdecl, 
    importc: "ASN1_TYPE_set_int_octetstring", dynlib: cryptodll.}
proc ASN1_TYPE_get_int_octetstring*(a: ptr ASN1_TYPE; num: ptr clong; 
                                    data: ptr cuchar; max_len: cint): cint {.
    cdecl, importc: "ASN1_TYPE_get_int_octetstring", dynlib: cryptodll.}
proc ASN1_seq_unpack*(buf: ptr cuchar; len: cint; d2i: ptr d2i_of_void; 
                      free_func: proc (a2: OPENSSL_BLOCK) {.cdecl.}): ptr stack_st_OPENSSL_BLOCK {.
    cdecl, importc: "ASN1_seq_unpack", dynlib: cryptodll.}
proc ASN1_seq_pack*(safes: ptr stack_st_OPENSSL_BLOCK; i2d: ptr i2d_of_void; 
                    buf: ptr ptr cuchar; len: ptr cint): ptr cuchar {.cdecl, 
    importc: "ASN1_seq_pack", dynlib: cryptodll.}
proc ASN1_unpack_string*(oct: ptr ASN1_STRING; d2i: ptr d2i_of_void): pointer {.
    cdecl, importc: "ASN1_unpack_string", dynlib: cryptodll.}
proc ASN1_item_unpack*(oct: ptr ASN1_STRING; it: ptr ASN1_ITEM): pointer {.
    cdecl, importc: "ASN1_item_unpack", dynlib: cryptodll.}
proc ASN1_pack_string*(obj: pointer; i2d: ptr i2d_of_void; 
                       oct: ptr ptr ASN1_OCTET_STRING): ptr ASN1_STRING {.cdecl, 
    importc: "ASN1_pack_string", dynlib: cryptodll.}
proc ASN1_item_pack*(obj: pointer; it: ptr ASN1_ITEM; 
                     oct: ptr ptr ASN1_OCTET_STRING): ptr ASN1_STRING {.cdecl, 
    importc: "ASN1_item_pack", dynlib: cryptodll.}
proc ASN1_STRING_set_default_mask*(mask: culong) {.cdecl, 
    importc: "ASN1_STRING_set_default_mask", dynlib: cryptodll.}
proc ASN1_STRING_set_default_mask_asc*(p: cstring): cint {.cdecl, 
    importc: "ASN1_STRING_set_default_mask_asc", dynlib: cryptodll.}
proc ASN1_STRING_get_default_mask*(): culong {.cdecl, 
    importc: "ASN1_STRING_get_default_mask", dynlib: cryptodll.}
proc ASN1_mbstring_copy*(output: ptr ptr ASN1_STRING; input: ptr cuchar; len: cint; 
                         inform: cint; mask: culong): cint {.cdecl, 
    importc: "ASN1_mbstring_copy", dynlib: cryptodll.}
proc ASN1_mbstring_ncopy*(output: ptr ptr ASN1_STRING; input: ptr cuchar; len: cint; 
                          inform: cint; mask: culong; minsize: clong; 
                          maxsize: clong): cint {.cdecl, 
    importc: "ASN1_mbstring_ncopy", dynlib: cryptodll.}
proc ASN1_STRING_set_by_NID*(output: ptr ptr ASN1_STRING; input: ptr cuchar; 
                             inlen: cint; inform: cint; nid: cint): ptr ASN1_STRING {.
    cdecl, importc: "ASN1_STRING_set_by_NID", dynlib: cryptodll.}
proc ASN1_STRING_TABLE_get*(nid: cint): ptr ASN1_STRING_TABLE {.cdecl, 
    importc: "ASN1_STRING_TABLE_get", dynlib: cryptodll.}
proc ASN1_STRING_TABLE_add*(a2: cint; a3: clong; a4: clong; a5: culong; 
                            a6: culong): cint {.cdecl, 
    importc: "ASN1_STRING_TABLE_add", dynlib: cryptodll.}
proc ASN1_STRING_TABLE_cleanup*() {.cdecl, importc: "ASN1_STRING_TABLE_cleanup", 
                                    dynlib: cryptodll.}
proc ASN1_item_new*(it: ptr ASN1_ITEM): ptr ASN1_VALUE {.cdecl, 
    importc: "ASN1_item_new", dynlib: cryptodll.}
proc ASN1_item_free*(val: ptr ASN1_VALUE; it: ptr ASN1_ITEM) {.cdecl, 
    importc: "ASN1_item_free", dynlib: cryptodll.}
proc ASN1_item_d2i*(val: ptr ptr ASN1_VALUE; input: ptr ptr cuchar; len: clong; 
                    it: ptr ASN1_ITEM): ptr ASN1_VALUE {.cdecl, 
    importc: "ASN1_item_d2i", dynlib: cryptodll.}
proc ASN1_item_i2d*(val: ptr ASN1_VALUE; output: ptr ptr cuchar; it: ptr ASN1_ITEM): cint {.
    cdecl, importc: "ASN1_item_i2d", dynlib: cryptodll.}
proc ASN1_item_ndef_i2d*(val: ptr ASN1_VALUE; output: ptr ptr cuchar; 
                         it: ptr ASN1_ITEM): cint {.cdecl, 
    importc: "ASN1_item_ndef_i2d", dynlib: cryptodll.}
proc ASN1_add_oid_module*() {.cdecl, importc: "ASN1_add_oid_module", 
                              dynlib: cryptodll.}
proc ASN1_generate_nconf*(str: cstring; nconf: ptr CONF): ptr ASN1_TYPE {.cdecl, 
    importc: "ASN1_generate_nconf", dynlib: cryptodll.}
proc ASN1_generate_v3*(str: cstring; cnf: ptr X509V3_CTX): ptr ASN1_TYPE {.
    cdecl, importc: "ASN1_generate_v3", dynlib: cryptodll.}
proc ASN1_item_print*(output: ptr BIO; ifld: ptr ASN1_VALUE; indent: cint; 
                      it: ptr ASN1_ITEM; pctx: ptr ASN1_PCTX): cint {.cdecl, 
    importc: "ASN1_item_print", dynlib: cryptodll.}
proc ASN1_PCTX_new*(): ptr ASN1_PCTX {.cdecl, importc: "ASN1_PCTX_new", 
                                       dynlib: cryptodll.}
proc ASN1_PCTX_free*(p: ptr ASN1_PCTX) {.cdecl, importc: "ASN1_PCTX_free", 
    dynlib: cryptodll.}
proc ASN1_PCTX_get_flags*(p: ptr ASN1_PCTX): culong {.cdecl, 
    importc: "ASN1_PCTX_get_flags", dynlib: cryptodll.}
proc ASN1_PCTX_set_flags*(p: ptr ASN1_PCTX; flags: culong) {.cdecl, 
    importc: "ASN1_PCTX_set_flags", dynlib: cryptodll.}
proc ASN1_PCTX_get_nm_flags*(p: ptr ASN1_PCTX): culong {.cdecl, 
    importc: "ASN1_PCTX_get_nm_flags", dynlib: cryptodll.}
proc ASN1_PCTX_set_nm_flags*(p: ptr ASN1_PCTX; flags: culong) {.cdecl, 
    importc: "ASN1_PCTX_set_nm_flags", dynlib: cryptodll.}
proc ASN1_PCTX_get_cert_flags*(p: ptr ASN1_PCTX): culong {.cdecl, 
    importc: "ASN1_PCTX_get_cert_flags", dynlib: cryptodll.}
proc ASN1_PCTX_set_cert_flags*(p: ptr ASN1_PCTX; flags: culong) {.cdecl, 
    importc: "ASN1_PCTX_set_cert_flags", dynlib: cryptodll.}
proc ASN1_PCTX_get_oid_flags*(p: ptr ASN1_PCTX): culong {.cdecl, 
    importc: "ASN1_PCTX_get_oid_flags", dynlib: cryptodll.}
proc ASN1_PCTX_set_oid_flags*(p: ptr ASN1_PCTX; flags: culong) {.cdecl, 
    importc: "ASN1_PCTX_set_oid_flags", dynlib: cryptodll.}
proc ASN1_PCTX_get_str_flags*(p: ptr ASN1_PCTX): culong {.cdecl, 
    importc: "ASN1_PCTX_get_str_flags", dynlib: cryptodll.}
proc ASN1_PCTX_set_str_flags*(p: ptr ASN1_PCTX; flags: culong) {.cdecl, 
    importc: "ASN1_PCTX_set_str_flags", dynlib: cryptodll.}
proc BIO_f_asn1*(): ptr BIO_METHOD {.cdecl, importc: "BIO_f_asn1", 
                                     dynlib: cryptodll.}
proc BIO_new_NDEF*(output: ptr BIO; val: ptr ASN1_VALUE; it: ptr ASN1_ITEM): ptr BIO {.
    cdecl, importc: "BIO_new_NDEF", dynlib: cryptodll.}
proc i2d_ASN1_bio_stream*(output: ptr BIO; val: ptr ASN1_VALUE; input: ptr BIO; 
                          flags: cint; it: ptr ASN1_ITEM): cint {.cdecl, 
    importc: "i2d_ASN1_bio_stream", dynlib: cryptodll.}
proc PEM_write_bio_ASN1_stream*(output: ptr BIO; val: ptr ASN1_VALUE; input: ptr BIO; 
                                flags: cint; hdr: cstring; it: ptr ASN1_ITEM): cint {.
    cdecl, importc: "PEM_write_bio_ASN1_stream", dynlib: cryptodll.}
proc SMIME_write_ASN1*(bio: ptr BIO; val: ptr ASN1_VALUE; data: ptr BIO; 
                       flags: cint; ctype_nid: cint; econt_nid: cint; 
                       mdalgs: ptr stack_st_X509_ALGOR; it: ptr ASN1_ITEM): cint {.
    cdecl, importc: "SMIME_write_ASN1", dynlib: cryptodll.}
proc SMIME_read_ASN1*(bio: ptr BIO; bcont: ptr ptr BIO; it: ptr ASN1_ITEM): ptr ASN1_VALUE {.
    cdecl, importc: "SMIME_read_ASN1", dynlib: cryptodll.}
proc SMIME_crlf_copy*(input: ptr BIO; output: ptr BIO; flags: cint): cint {.cdecl, 
    importc: "SMIME_crlf_copy", dynlib: cryptodll.}
proc SMIME_text*(input: ptr BIO; output: ptr BIO): cint {.cdecl, 
    importc: "SMIME_text", dynlib: cryptodll.}
proc ERR_load_ASN1_strings*() {.cdecl, importc: "ERR_load_ASN1_strings", 
                                dynlib: cryptodll.}


proc OBJ_NAME_init*(): cint {.cdecl, importc: "OBJ_NAME_init", dynlib: cryptodll.}
proc OBJ_NAME_new_index*(hash_func: proc (a2: cstring): culong {.cdecl.}; 
    cmp_func: proc (a2: cstring; a3: cstring): cint {.cdecl.}; free_func: proc (
    a2: cstring; a3: cint; a4: cstring) {.cdecl.}): cint {.cdecl, 
    importc: "OBJ_NAME_new_index", dynlib: cryptodll.}
proc OBJ_NAME_get*(name: cstring; typ: cint): cstring {.cdecl, 
    importc: "OBJ_NAME_get", dynlib: cryptodll.}
proc OBJ_NAME_add*(name: cstring; typ: cint; data: cstring): cint {.cdecl, 
    importc: "OBJ_NAME_add", dynlib: cryptodll.}
proc OBJ_NAME_remove*(name: cstring; typ: cint): cint {.cdecl, 
    importc: "OBJ_NAME_remove", dynlib: cryptodll.}
proc OBJ_NAME_cleanup*(typ: cint) {.cdecl, importc: "OBJ_NAME_cleanup", 
                                     dynlib: cryptodll.}
proc OBJ_NAME_do_all*(typ: cint; 
                      fn: proc (a2: ptr OBJ_NAME; arg: pointer) {.cdecl.}; 
                      arg: pointer) {.cdecl, importc: "OBJ_NAME_do_all", 
                                      dynlib: cryptodll.}
proc OBJ_NAME_do_all_sorted*(typ: cint; fn: proc (a2: ptr OBJ_NAME; 
    arg: pointer) {.cdecl.}; arg: pointer) {.cdecl, 
    importc: "OBJ_NAME_do_all_sorted", dynlib: cryptodll.}
proc OBJ_dup*(o: ptr ASN1_OBJECT): ptr ASN1_OBJECT {.cdecl, importc: "OBJ_dup", 
    dynlib: cryptodll.}
proc OBJ_nid2obj*(n: cint): ptr ASN1_OBJECT {.cdecl, importc: "OBJ_nid2obj", 
    dynlib: cryptodll.}
proc OBJ_nid2ln*(n: cint): cstring {.cdecl, importc: "OBJ_nid2ln", 
                                     dynlib: cryptodll.}
proc OBJ_nid2sn*(n: cint): cstring {.cdecl, importc: "OBJ_nid2sn", 
                                     dynlib: cryptodll.}
proc OBJ_obj2nid*(o: ptr ASN1_OBJECT): cint {.cdecl, importc: "OBJ_obj2nid", 
    dynlib: cryptodll.}
proc OBJ_txt2obj*(s: cstring; no_name: cint): ptr ASN1_OBJECT {.cdecl, 
    importc: "OBJ_txt2obj", dynlib: cryptodll.}
proc OBJ_obj2txt*(buf: cstring; buf_len: cint; a: ptr ASN1_OBJECT; no_name: cint): cint {.
    cdecl, importc: "OBJ_obj2txt", dynlib: cryptodll.}
proc OBJ_txt2nid*(s: cstring): cint {.cdecl, importc: "OBJ_txt2nid", 
                                      dynlib: cryptodll.}
proc OBJ_ln2nid*(s: cstring): cint {.cdecl, importc: "OBJ_ln2nid", 
                                     dynlib: cryptodll.}
proc OBJ_sn2nid*(s: cstring): cint {.cdecl, importc: "OBJ_sn2nid", 
                                     dynlib: cryptodll.}
proc OBJ_cmp*(a: ptr ASN1_OBJECT; b: ptr ASN1_OBJECT): cint {.cdecl, 
    importc: "OBJ_cmp", dynlib: cryptodll.}
proc OBJ_bsearch*(key: pointer; base: pointer; num: cint; size: cint; 
                   cmp: proc (a2: pointer; a3: pointer): cint {.cdecl.}): pointer {.
    cdecl, importc: "OBJ_bsearch_", dynlib: cryptodll.}
proc OBJ_bsearch_ex*(key: pointer; base: pointer; num: cint; size: cint; 
                      cmp: proc (a2: pointer; a3: pointer): cint {.cdecl.}; 
                      flags: cint): pointer {.cdecl, importc: "OBJ_bsearch_ex_", 
    dynlib: cryptodll.}
proc OBJ_new_nid*(num: cint): cint {.cdecl, importc: "OBJ_new_nid", 
                                     dynlib: cryptodll.}
proc OBJ_add_object*(obj: ptr ASN1_OBJECT): cint {.cdecl, 
    importc: "OBJ_add_object", dynlib: cryptodll.}
proc OBJ_create*(oid: cstring; sn: cstring; ln: cstring): cint {.cdecl, 
    importc: "OBJ_create", dynlib: cryptodll.}
proc OBJ_cleanup*() {.cdecl, importc: "OBJ_cleanup", dynlib: cryptodll.}
proc OBJ_create_objects*(input: ptr BIO): cint {.cdecl, 
    importc: "OBJ_create_objects", dynlib: cryptodll.}
proc OBJ_find_sigid_algs*(signid: cint; pdig_nid: ptr cint; ppkey_nid: ptr cint): cint {.
    cdecl, importc: "OBJ_find_sigid_algs", dynlib: cryptodll.}
proc OBJ_find_sigid_by_algs*(psignid: ptr cint; dig_nid: cint; pkey_nid: cint): cint {.
    cdecl, importc: "OBJ_find_sigid_by_algs", dynlib: cryptodll.}
proc OBJ_add_sigid*(signid: cint; dig_id: cint; pkey_id: cint): cint {.cdecl, 
    importc: "OBJ_add_sigid", dynlib: cryptodll.}
proc OBJ_sigid_free*() {.cdecl, importc: "OBJ_sigid_free", dynlib: cryptodll.}
var obj_cleanup_defer* {.importc: "obj_cleanup_defer", dynlib: cryptodll.}: cint

proc check_defer*(nid: cint) {.cdecl, importc: "check_defer", dynlib: cryptodll.}
proc ERR_load_OBJ_strings*() {.cdecl, importc: "ERR_load_OBJ_strings", 
                               dynlib: cryptodll.}
