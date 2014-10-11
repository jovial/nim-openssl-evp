type 
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
                         idx: cint; argl: clong; argp: pointer): cint
  CRYPTO_EX_free* = proc (parent: pointer; pntr: pointer; 
                          ad: ptr CRYPTO_EX_DATA; idx: cint; argl: clong; 
                          argp: pointer)
  CRYPTO_EX_dup* = proc (to: ptr CRYPTO_EX_DATA; frm: ptr CRYPTO_EX_DATA; 
                         from_d: pointer; idx: cint; argl: clong; argp: pointer): cint
  OCSP_REQ_CTX* = ocsp_req_ctx_st
  OCSP_RESPONSE* = ocsp_response_st
  OCSP_RESPID* = ocsp_responder_id_st
  mStack* {.importc: "_STACK", header: "openssl/evp.h".} = object 
    num* {.importc: "num".}: cint
    data* {.importc: "data".}: cstringArray
    sorted* {.importc: "sorted".}: cint
    num_alloc* {.importc: "num_alloc".}: cint
    comp* {.importc: "comp".}: proc (a2: pointer; a3: pointer): cint


proc sk_num*(a2: ptr mStack): cint {.importc: "sk_num", header: "openssl/evp.h".}
proc sk_value*(a2: ptr mStack; a3: cint): pointer {.importc: "sk_value", 
    header: "openssl/evp.h".}
proc sk_set*(a2: ptr mStack; a3: cint; a4: pointer): pointer {.
    importc: "sk_set", header: "openssl/evp.h".}
proc sk_new*(cmp: proc (a2: pointer; a3: pointer): cint): ptr mStack {.
    importc: "sk_new", header: "openssl/evp.h".}
proc sk_new_null*(): ptr mStack {.importc: "sk_new_null", 
                                  header: "openssl/evp.h".}
proc sk_free*(a2: ptr mStack) {.importc: "sk_free", header: "openssl/evp.h".}
proc sk_pop_free*(st: ptr mStack; func: proc (a2: pointer)) {.
    importc: "sk_pop_free", header: "openssl/evp.h".}
proc sk_insert*(sk: ptr mStack; data: pointer; where: cint): cint {.
    importc: "sk_insert", header: "openssl/evp.h".}
proc sk_delete*(st: ptr mStack; loc: cint): pointer {.importc: "sk_delete", 
    header: "openssl/evp.h".}
proc sk_delete_ptr*(st: ptr mStack; p: pointer): pointer {.
    importc: "sk_delete_ptr", header: "openssl/evp.h".}
proc sk_find*(st: ptr mStack; data: pointer): cint {.importc: "sk_find", 
    header: "openssl/evp.h".}
proc sk_find_ex*(st: ptr mStack; data: pointer): cint {.importc: "sk_find_ex", 
    header: "openssl/evp.h".}
proc sk_push*(st: ptr mStack; data: pointer): cint {.importc: "sk_push", 
    header: "openssl/evp.h".}
proc sk_unshift*(st: ptr mStack; data: pointer): cint {.importc: "sk_unshift", 
    header: "openssl/evp.h".}
proc sk_shift*(st: ptr mStack): pointer {.importc: "sk_shift", 
    header: "openssl/evp.h".}
proc sk_pop*(st: ptr mStack): pointer {.importc: "sk_pop", 
                                        header: "openssl/evp.h".}
proc sk_zero*(st: ptr mStack) {.importc: "sk_zero", header: "openssl/evp.h".}
#int (*sk_set_cmp_func(_STACK *sk, int (*c)(const void *, const void *)))
# (const void *, const void *);

proc sk_dup*(st: ptr mStack): ptr mStack {.importc: "sk_dup", 
    header: "openssl/evp.h".}
proc sk_sort*(st: ptr mStack) {.importc: "sk_sort", header: "openssl/evp.h".}
proc sk_is_sorted*(st: ptr mStack): cint {.importc: "sk_is_sorted", 
    header: "openssl/evp.h".}
type 
  OPENSSL_STRING* = cstring
  OPENSSL_CSTRING* = cstring
  stack_st_OPENSSL_STRING* {.importc: "stack_st_OPENSSL_STRING", 
                             header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  OPENSSL_BLOCK* = pointer
  stack_st_OPENSSL_BLOCK* {.importc: "stack_st_OPENSSL_BLOCK", 
                            header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  OPENSSL_ITEM* {.importc: "OPENSSL_ITEM", header: "openssl/evp.h".} = object 
    code* {.importc: "code".}: cint
    value* {.importc: "value".}: pointer
    value_size* {.importc: "value_size".}: csize
    value_length* {.importc: "value_length".}: ptr csize

  CRYPTO_dynlock* {.importc: "CRYPTO_dynlock", header: "openssl/evp.h".} = object 
    references* {.importc: "references".}: cint
    data* {.importc: "data".}: ptr CRYPTO_dynlock_value

  BIO_dummy* = bio_st
  crypto_ex_data_st* {.importc: "crypto_ex_data_st", header: "openssl/evp.h".} = object 
    sk* {.importc: "sk".}: ptr stack_st_void
    dummy* {.importc: "dummy".}: cint

  stack_st_void* {.importc: "stack_st_void", header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  CRYPTO_EX_DATA_FUNCS* {.importc: "CRYPTO_EX_DATA_FUNCS", 
                          header: "openssl/evp.h".} = object 
    argl* {.importc: "argl".}: clong
    argp* {.importc: "argp".}: pointer
    new_func* {.importc: "new_func".}: ptr CRYPTO_EX_new
    free_func* {.importc: "free_func".}: ptr CRYPTO_EX_free
    dup_func* {.importc: "dup_func".}: ptr CRYPTO_EX_dup

  stack_st_CRYPTO_EX_DATA_FUNCS* {.importc: "stack_st_CRYPTO_EX_DATA_FUNCS", 
                                   header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack


proc CRYPTO_mem_ctrl*(mode: cint): cint {.importc: "CRYPTO_mem_ctrl", 
    header: "openssl/evp.h".}
proc CRYPTO_is_mem_check_on*(): cint {.importc: "CRYPTO_is_mem_check_on", 
                                       header: "openssl/evp.h".}
proc SSLeay_version*(typ: cint): cstring {.importc: "SSLeay_version", 
    header: "openssl/evp.h".}
proc SSLeay*(): culong {.importc: "SSLeay", header: "openssl/evp.h".}
proc OPENSSL_issetugid*(): cint {.importc: "OPENSSL_issetugid", 
                                  header: "openssl/evp.h".}
type 
  CRYPTO_EX_DATA_IMPL* = st_CRYPTO_EX_DATA_IMPL

proc CRYPTO_get_ex_data_implementation*(): ptr CRYPTO_EX_DATA_IMPL {.
    importc: "CRYPTO_get_ex_data_implementation", header: "openssl/evp.h".}
proc CRYPTO_set_ex_data_implementation*(i: ptr CRYPTO_EX_DATA_IMPL): cint {.
    importc: "CRYPTO_set_ex_data_implementation", header: "openssl/evp.h".}
proc CRYPTO_ex_data_new_class*(): cint {.importc: "CRYPTO_ex_data_new_class", 
    header: "openssl/evp.h".}
proc CRYPTO_get_ex_new_index*(class_index: cint; argl: clong; argp: pointer; 
                              new_func: ptr CRYPTO_EX_new; 
                              dup_func: ptr CRYPTO_EX_dup; 
                              free_func: ptr CRYPTO_EX_free): cint {.
    importc: "CRYPTO_get_ex_new_index", header: "openssl/evp.h".}
proc CRYPTO_new_ex_data*(class_index: cint; obj: pointer; ad: ptr CRYPTO_EX_DATA): cint {.
    importc: "CRYPTO_new_ex_data", header: "openssl/evp.h".}
proc CRYPTO_dup_ex_data*(class_index: cint; to: ptr CRYPTO_EX_DATA; 
                         frm: ptr CRYPTO_EX_DATA): cint {.
    importc: "CRYPTO_dup_ex_data", header: "openssl/evp.h".}
proc CRYPTO_free_ex_data*(class_index: cint; obj: pointer; 
                          ad: ptr CRYPTO_EX_DATA) {.
    importc: "CRYPTO_free_ex_data", header: "openssl/evp.h".}
proc CRYPTO_set_ex_data*(ad: ptr CRYPTO_EX_DATA; idx: cint; val: pointer): cint {.
    importc: "CRYPTO_set_ex_data", header: "openssl/evp.h".}
proc CRYPTO_get_ex_data*(ad: ptr CRYPTO_EX_DATA; idx: cint): pointer {.
    importc: "CRYPTO_get_ex_data", header: "openssl/evp.h".}
proc CRYPTO_cleanup_all_ex_data*() {.importc: "CRYPTO_cleanup_all_ex_data", 
                                     header: "openssl/evp.h".}
proc CRYPTO_get_new_lockid*(name: cstring): cint {.
    importc: "CRYPTO_get_new_lockid", header: "openssl/evp.h".}
proc CRYPTO_num_locks*(): cint {.importc: "CRYPTO_num_locks", 
                                 header: "openssl/evp.h".}
proc CRYPTO_lock*(mode: cint; typ: cint; file: cstring; line: cint) {.
    importc: "CRYPTO_lock", header: "openssl/evp.h".}
#void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
#           const char *file,int line));
#void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
#  int line);
#void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type,
#           const char *file, int line));
#int (*CRYPTO_get_add_lock_callback(void))(int *num,int mount,int type,
#       const char *file,int line);

type 
  CRYPTO_THREADID* {.importc: "CRYPTO_THREADID", header: "openssl/evp.h".} = object 
    pntr* {.importc: "ptr".}: pointer
    val* {.importc: "val".}: culong


proc CRYPTO_THREADID_set_numeric*(id: ptr CRYPTO_THREADID; val: culong) {.
    importc: "CRYPTO_THREADID_set_numeric", header: "openssl/evp.h".}
proc CRYPTO_THREADID_set_pointer*(id: ptr CRYPTO_THREADID; pntr: pointer) {.
    importc: "CRYPTO_THREADID_set_pointer", header: "openssl/evp.h".}
proc CRYPTO_THREADID_set_callback*(threadid_func: proc (a2: ptr CRYPTO_THREADID)): cint {.
    importc: "CRYPTO_THREADID_set_callback", header: "openssl/evp.h".}
#void (*CRYPTO_THREADID_get_callback(void))(CRYPTO_THREADID *);

proc CRYPTO_THREADID_current*(id: ptr CRYPTO_THREADID) {.
    importc: "CRYPTO_THREADID_current", header: "openssl/evp.h".}
proc CRYPTO_THREADID_cmp*(a: ptr CRYPTO_THREADID; b: ptr CRYPTO_THREADID): cint {.
    importc: "CRYPTO_THREADID_cmp", header: "openssl/evp.h".}
proc CRYPTO_THREADID_cpy*(dest: ptr CRYPTO_THREADID; src: ptr CRYPTO_THREADID) {.
    importc: "CRYPTO_THREADID_cpy", header: "openssl/evp.h".}
proc CRYPTO_THREADID_hash*(id: ptr CRYPTO_THREADID): culong {.
    importc: "CRYPTO_THREADID_hash", header: "openssl/evp.h".}
proc CRYPTO_set_id_callback*(func: proc (): culong) {.
    importc: "CRYPTO_set_id_callback", header: "openssl/evp.h".}
#unsigned long (*CRYPTO_get_id_callback(void))(void);

proc CRYPTO_thread_id*(): culong {.importc: "CRYPTO_thread_id", 
                                   header: "openssl/evp.h".}
proc CRYPTO_get_lock_name*(typ: cint): cstring {.
    importc: "CRYPTO_get_lock_name", header: "openssl/evp.h".}
proc CRYPTO_add_lock*(pointer: ptr cint; amount: cint; typ: cint; file: cstring; 
                      line: cint): cint {.importc: "CRYPTO_add_lock", 
    header: "openssl/evp.h".}
proc CRYPTO_get_new_dynlockid*(): cint {.importc: "CRYPTO_get_new_dynlockid", 
    header: "openssl/evp.h".}
proc CRYPTO_destroy_dynlockid*(i: cint) {.importc: "CRYPTO_destroy_dynlockid", 
    header: "openssl/evp.h".}
proc CRYPTO_get_dynlock_value*(i: cint): ptr CRYPTO_dynlock_value {.
    importc: "CRYPTO_get_dynlock_value", header: "openssl/evp.h".}
proc CRYPTO_set_dynlock_create_callback*(dyn_create_function: proc (
    file: cstring; line: cint): ptr CRYPTO_dynlock_value) {.
    importc: "CRYPTO_set_dynlock_create_callback", header: "openssl/evp.h".}
proc CRYPTO_set_dynlock_lock_callback*(dyn_lock_function: proc (mode: cint; 
    l: ptr CRYPTO_dynlock_value; file: cstring; line: cint)) {.
    importc: "CRYPTO_set_dynlock_lock_callback", header: "openssl/evp.h".}
proc CRYPTO_set_dynlock_destroy_callback*(dyn_destroy_function: proc (
    l: ptr CRYPTO_dynlock_value; file: cstring; line: cint)) {.
    importc: "CRYPTO_set_dynlock_destroy_callback", header: "openssl/evp.h".}
#struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))(const char *file,int line);
#void (*CRYPTO_get_dynlock_lock_callback(void))(int mode, struct CRYPTO_dynlock_value *l, const char *file,int line);
#void (*CRYPTO_get_dynlock_destroy_callback(void))(struct CRYPTO_dynlock_value *l, const char *file,int line);

proc CRYPTO_set_mem_functions*(m: proc (a2: csize): pointer; 
                               r: proc (a2: pointer; a3: csize): pointer; 
                               f: proc (a2: pointer)): cint {.
    importc: "CRYPTO_set_mem_functions", header: "openssl/evp.h".}
proc CRYPTO_set_locked_mem_functions*(m: proc (a2: csize): pointer; 
                                      free_func: proc (a2: pointer)): cint {.
    importc: "CRYPTO_set_locked_mem_functions", header: "openssl/evp.h".}
proc CRYPTO_set_mem_ex_functions*(m: proc (a2: csize; a3: cstring; a4: cint): pointer; 
    r: proc (a2: pointer; a3: csize; a4: cstring; a5: cint): pointer; 
                                  f: proc (a2: pointer)): cint {.
    importc: "CRYPTO_set_mem_ex_functions", header: "openssl/evp.h".}
proc CRYPTO_set_locked_mem_ex_functions*(
    m: proc (a2: csize; a3: cstring; a4: cint): pointer; 
    free_func: proc (a2: pointer)): cint {.
    importc: "CRYPTO_set_locked_mem_ex_functions", header: "openssl/evp.h".}
proc CRYPTO_set_mem_debug_functions*(m: proc (a2: pointer; a3: cint; 
    a4: cstring; a5: cint; a6: cint); r: proc (a2: pointer; a3: pointer; 
    a4: cint; a5: cstring; a6: cint; a7: cint); f: proc (a2: pointer; a3: cint); 
                                     so: proc (a2: clong); go: proc (): clong): cint {.
    importc: "CRYPTO_set_mem_debug_functions", header: "openssl/evp.h".}
proc CRYPTO_get_mem_functions*(m: proc (a2: csize): pointer; 
                               r: proc (a2: pointer; a3: csize): pointer; 
                               f: proc (a2: pointer)) {.
    importc: "CRYPTO_get_mem_functions", header: "openssl/evp.h".}
proc CRYPTO_get_locked_mem_functions*(m: proc (a2: csize): pointer; 
                                      f: proc (a2: pointer)) {.
    importc: "CRYPTO_get_locked_mem_functions", header: "openssl/evp.h".}
proc CRYPTO_get_mem_ex_functions*(m: proc (a2: csize; a3: cstring; a4: cint): pointer; 
    r: proc (a2: pointer; a3: csize; a4: cstring; a5: cint): pointer; 
                                  f: proc (a2: pointer)) {.
    importc: "CRYPTO_get_mem_ex_functions", header: "openssl/evp.h".}
proc CRYPTO_get_locked_mem_ex_functions*(
    m: proc (a2: csize; a3: cstring; a4: cint): pointer; f: proc (a2: pointer)) {.
    importc: "CRYPTO_get_locked_mem_ex_functions", header: "openssl/evp.h".}
proc CRYPTO_get_mem_debug_functions*(m: proc (a2: pointer; a3: cint; 
    a4: cstring; a5: cint; a6: cint); r: proc (a2: pointer; a3: pointer; 
    a4: cint; a5: cstring; a6: cint; a7: cint); f: proc (a2: pointer; a3: cint); 
                                     so: proc (a2: clong); go: proc (): clong) {.
    importc: "CRYPTO_get_mem_debug_functions", header: "openssl/evp.h".}
proc CRYPTO_malloc_locked*(num: cint; file: cstring; line: cint): pointer {.
    importc: "CRYPTO_malloc_locked", header: "openssl/evp.h".}
proc CRYPTO_free_locked*(pntr: pointer) {.importc: "CRYPTO_free_locked", 
    header: "openssl/evp.h".}
proc CRYPTO_malloc*(num: cint; file: cstring; line: cint): pointer {.
    importc: "CRYPTO_malloc", header: "openssl/evp.h".}
proc CRYPTO_strdup*(str: cstring; file: cstring; line: cint): cstring {.
    importc: "CRYPTO_strdup", header: "openssl/evp.h".}
proc CRYPTO_free*(pntr: pointer) {.importc: "CRYPTO_free", 
                                   header: "openssl/evp.h".}
proc CRYPTO_realloc*(addr: pointer; num: cint; file: cstring; line: cint): pointer {.
    importc: "CRYPTO_realloc", header: "openssl/evp.h".}
proc CRYPTO_realloc_clean*(addr: pointer; old_num: cint; num: cint; 
                           file: cstring; line: cint): pointer {.
    importc: "CRYPTO_realloc_clean", header: "openssl/evp.h".}
proc CRYPTO_remalloc*(addr: pointer; num: cint; file: cstring; line: cint): pointer {.
    importc: "CRYPTO_remalloc", header: "openssl/evp.h".}
proc OPENSSL_cleanse*(pntr: pointer; len: csize) {.importc: "OPENSSL_cleanse", 
    header: "openssl/evp.h".}
proc CRYPTO_set_mem_debug_options*(bits: clong) {.
    importc: "CRYPTO_set_mem_debug_options", header: "openssl/evp.h".}
proc CRYPTO_get_mem_debug_options*(): clong {.
    importc: "CRYPTO_get_mem_debug_options", header: "openssl/evp.h".}
proc CRYPTO_push_info_*(info: cstring; file: cstring; line: cint): cint {.
    importc: "CRYPTO_push_info_", header: "openssl/evp.h".}
proc CRYPTO_pop_info*(): cint {.importc: "CRYPTO_pop_info", 
                                header: "openssl/evp.h".}
proc CRYPTO_remove_all_info*(): cint {.importc: "CRYPTO_remove_all_info", 
                                       header: "openssl/evp.h".}
proc CRYPTO_dbg_malloc*(addr: pointer; num: cint; file: cstring; line: cint; 
                        before_p: cint) {.importc: "CRYPTO_dbg_malloc", 
    header: "openssl/evp.h".}
proc CRYPTO_dbg_realloc*(addr1: pointer; addr2: pointer; num: cint; 
                         file: cstring; line: cint; before_p: cint) {.
    importc: "CRYPTO_dbg_realloc", header: "openssl/evp.h".}
proc CRYPTO_dbg_free*(addr: pointer; before_p: cint) {.
    importc: "CRYPTO_dbg_free", header: "openssl/evp.h".}
proc CRYPTO_dbg_set_options*(bits: clong) {.importc: "CRYPTO_dbg_set_options", 
    header: "openssl/evp.h".}
proc CRYPTO_dbg_get_options*(): clong {.importc: "CRYPTO_dbg_get_options", 
                                        header: "openssl/evp.h".}
proc CRYPTO_mem_leaks_fp*(a2: ptr FILE) {.importc: "CRYPTO_mem_leaks_fp", 
    header: "openssl/evp.h".}
proc CRYPTO_mem_leaks*(bio: ptr bio_st) {.importc: "CRYPTO_mem_leaks", 
    header: "openssl/evp.h".}
type 
  CRYPTO_MEM_LEAK_CB* = proc (a2: culong; a3: cstring; a4: cint; a5: cint; 
                              a6: pointer): pointer

proc CRYPTO_mem_leaks_cb*(cb: ptr CRYPTO_MEM_LEAK_CB) {.
    importc: "CRYPTO_mem_leaks_cb", header: "openssl/evp.h".}
proc OpenSSLDie*(file: cstring; line: cint; assertion: cstring) {.
    importc: "OpenSSLDie", header: "openssl/evp.h".}
proc OPENSSL_ia32cap_loc*(): ptr culong {.importc: "OPENSSL_ia32cap_loc", 
    header: "openssl/evp.h".}
proc OPENSSL_isservice*(): cint {.importc: "OPENSSL_isservice", 
                                  header: "openssl/evp.h".}
proc FIPS_mode*(): cint {.importc: "FIPS_mode", header: "openssl/evp.h".}
proc FIPS_mode_set*(r: cint): cint {.importc: "FIPS_mode_set", 
                                     header: "openssl/evp.h".}
proc OPENSSL_init*() {.importc: "OPENSSL_init", header: "openssl/evp.h".}
proc CRYPTO_memcmp*(a: pointer; b: pointer; len: csize): cint {.
    importc: "CRYPTO_memcmp", header: "openssl/evp.h".}
proc ERR_load_CRYPTO_strings*() {.importc: "ERR_load_CRYPTO_strings", 
                                  header: "openssl/evp.h".}
type 
  BIO* = bio_st

proc BIO_set_flags*(b: ptr BIO; flags: cint) {.importc: "BIO_set_flags", 
    header: "openssl/evp.h".}
proc BIO_test_flags*(b: ptr BIO; flags: cint): cint {.importc: "BIO_test_flags", 
    header: "openssl/evp.h".}
proc BIO_clear_flags*(b: ptr BIO; flags: cint) {.importc: "BIO_clear_flags", 
    header: "openssl/evp.h".}
#long (*BIO_get_callback(const BIO *b)) (struct bio_st *,int,const char *,int, long,long);

proc BIO_set_callback*(b: ptr BIO; callback: proc (a2: ptr bio_st; a3: cint; 
    a4: cstring; a5: cint; a6: clong; a7: clong): clong) {.
    importc: "BIO_set_callback", header: "openssl/evp.h".}
proc BIO_get_callback_arg*(b: ptr BIO): cstring {.
    importc: "BIO_get_callback_arg", header: "openssl/evp.h".}
proc BIO_set_callback_arg*(b: ptr BIO; arg: cstring) {.
    importc: "BIO_set_callback_arg", header: "openssl/evp.h".}
proc BIO_method_name*(b: ptr BIO): cstring {.importc: "BIO_method_name", 
    header: "openssl/evp.h".}
proc BIO_method_type*(b: ptr BIO): cint {.importc: "BIO_method_type", 
    header: "openssl/evp.h".}
type 
  bio_info_cb* = proc (a2: ptr bio_st; a3: cint; a4: cstring; a5: cint; 
                       a6: clong; a7: clong)
  BIO_METHOD* {.importc: "BIO_METHOD", header: "openssl/evp.h".} = object 
    typ* {.importc: "type".}: cint
    name* {.importc: "name".}: cstring
    bwrite* {.importc: "bwrite".}: proc (a2: ptr BIO; a3: cstring; a4: cint): cint
    bread* {.importc: "bread".}: proc (a2: ptr BIO; a3: cstring; a4: cint): cint
    bputs* {.importc: "bputs".}: proc (a2: ptr BIO; a3: cstring): cint
    bgets* {.importc: "bgets".}: proc (a2: ptr BIO; a3: cstring; a4: cint): cint
    ctrl* {.importc: "ctrl".}: proc (a2: ptr BIO; a3: cint; a4: clong; 
                                     a5: pointer): clong
    create* {.importc: "create".}: proc (a2: ptr BIO): cint
    destroy* {.importc: "destroy".}: proc (a2: ptr BIO): cint
    callback_ctrl* {.importc: "callback_ctrl".}: proc (a2: ptr BIO; a3: cint; 
        a4: ptr bio_info_cb): clong

  bio_st* {.importc: "bio_st", header: "openssl/evp.h".} = object 
    method* {.importc: "method".}: ptr BIO_METHOD
    callback* {.importc: "callback".}: proc (a2: ptr bio_st; a3: cint; 
        a4: cstring; a5: cint; a6: clong; a7: clong): clong
    cb_arg* {.importc: "cb_arg".}: cstring
    init* {.importc: "init".}: cint
    shutdown* {.importc: "shutdown".}: cint
    flags* {.importc: "flags".}: cint
    retry_reason* {.importc: "retry_reason".}: cint
    num* {.importc: "num".}: cint
    pntr* {.importc: "ptr".}: pointer
    next_bio* {.importc: "next_bio".}: ptr bio_st
    prev_bio* {.importc: "prev_bio".}: ptr bio_st
    references* {.importc: "references".}: cint
    num_read* {.importc: "num_read".}: culong
    num_write* {.importc: "num_write".}: culong
    ex_data* {.importc: "ex_data".}: CRYPTO_EX_DATA

  stack_st_BIO* {.importc: "stack_st_BIO", header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  BIO_F_BUFFER_CTX* {.importc: "BIO_F_BUFFER_CTX", header: "openssl/evp.h".} = object 
    ibuf_size* {.importc: "ibuf_size".}: cint
    obuf_size* {.importc: "obuf_size".}: cint
    ibuf* {.importc: "ibuf".}: cstring
    ibuf_len* {.importc: "ibuf_len".}: cint
    ibuf_off* {.importc: "ibuf_off".}: cint
    obuf* {.importc: "obuf".}: cstring
    obuf_len* {.importc: "obuf_len".}: cint
    obuf_off* {.importc: "obuf_off".}: cint

  asn1_ps_func* = proc (b: ptr BIO; pbuf: ptr ptr cuchar; plen: ptr cint; 
                        parg: pointer): cint

proc BIO_ctrl_pending*(b: ptr BIO): csize {.importc: "BIO_ctrl_pending", 
    header: "openssl/evp.h".}
proc BIO_ctrl_wpending*(b: ptr BIO): csize {.importc: "BIO_ctrl_wpending", 
    header: "openssl/evp.h".}
proc BIO_ctrl_get_write_guarantee*(b: ptr BIO): csize {.
    importc: "BIO_ctrl_get_write_guarantee", header: "openssl/evp.h".}
proc BIO_ctrl_get_read_request*(b: ptr BIO): csize {.
    importc: "BIO_ctrl_get_read_request", header: "openssl/evp.h".}
proc BIO_ctrl_reset_read_request*(b: ptr BIO): cint {.
    importc: "BIO_ctrl_reset_read_request", header: "openssl/evp.h".}
proc BIO_set_ex_data*(bio: ptr BIO; idx: cint; data: pointer): cint {.
    importc: "BIO_set_ex_data", header: "openssl/evp.h".}
proc BIO_get_ex_data*(bio: ptr BIO; idx: cint): pointer {.
    importc: "BIO_get_ex_data", header: "openssl/evp.h".}
proc BIO_get_ex_new_index*(argl: clong; argp: pointer; 
                           new_func: ptr CRYPTO_EX_new; 
                           dup_func: ptr CRYPTO_EX_dup; 
                           free_func: ptr CRYPTO_EX_free): cint {.
    importc: "BIO_get_ex_new_index", header: "openssl/evp.h".}
proc BIO_number_read*(bio: ptr BIO): culong {.importc: "BIO_number_read", 
    header: "openssl/evp.h".}
proc BIO_number_written*(bio: ptr BIO): culong {.importc: "BIO_number_written", 
    header: "openssl/evp.h".}
proc BIO_asn1_set_prefix*(b: ptr BIO; prefix: ptr asn1_ps_func; 
                          prefix_free: ptr asn1_ps_func): cint {.
    importc: "BIO_asn1_set_prefix", header: "openssl/evp.h".}
proc BIO_asn1_get_prefix*(b: ptr BIO; pprefix: ptr ptr asn1_ps_func; 
                          pprefix_free: ptr ptr asn1_ps_func): cint {.
    importc: "BIO_asn1_get_prefix", header: "openssl/evp.h".}
proc BIO_asn1_set_suffix*(b: ptr BIO; suffix: ptr asn1_ps_func; 
                          suffix_free: ptr asn1_ps_func): cint {.
    importc: "BIO_asn1_set_suffix", header: "openssl/evp.h".}
proc BIO_asn1_get_suffix*(b: ptr BIO; psuffix: ptr ptr asn1_ps_func; 
                          psuffix_free: ptr ptr asn1_ps_func): cint {.
    importc: "BIO_asn1_get_suffix", header: "openssl/evp.h".}
proc BIO_s_file*(): ptr BIO_METHOD {.importc: "BIO_s_file", 
                                     header: "openssl/evp.h".}
proc BIO_new_file*(filename: cstring; mode: cstring): ptr BIO {.
    importc: "BIO_new_file", header: "openssl/evp.h".}
proc BIO_new_fp*(stream: ptr FILE; close_flag: cint): ptr BIO {.
    importc: "BIO_new_fp", header: "openssl/evp.h".}
proc BIO_new*(typ: ptr BIO_METHOD): ptr BIO {.importc: "BIO_new", 
    header: "openssl/evp.h".}
proc BIO_set*(a: ptr BIO; typ: ptr BIO_METHOD): cint {.importc: "BIO_set", 
    header: "openssl/evp.h".}
proc BIO_free*(a: ptr BIO): cint {.importc: "BIO_free", header: "openssl/evp.h".}
proc BIO_vfree*(a: ptr BIO) {.importc: "BIO_vfree", header: "openssl/evp.h".}
proc BIO_read*(b: ptr BIO; data: pointer; len: cint): cint {.
    importc: "BIO_read", header: "openssl/evp.h".}
proc BIO_gets*(bp: ptr BIO; buf: cstring; size: cint): cint {.
    importc: "BIO_gets", header: "openssl/evp.h".}
proc BIO_write*(b: ptr BIO; data: pointer; len: cint): cint {.
    importc: "BIO_write", header: "openssl/evp.h".}
proc BIO_puts*(bp: ptr BIO; buf: cstring): cint {.importc: "BIO_puts", 
    header: "openssl/evp.h".}
proc BIO_indent*(b: ptr BIO; indent: cint; max: cint): cint {.
    importc: "BIO_indent", header: "openssl/evp.h".}
proc BIO_ctrl*(bp: ptr BIO; cmd: cint; larg: clong; parg: pointer): clong {.
    importc: "BIO_ctrl", header: "openssl/evp.h".}
proc BIO_callback_ctrl*(b: ptr BIO; cmd: cint; fp: proc (a2: ptr bio_st; 
    a3: cint; a4: cstring; a5: cint; a6: clong; a7: clong)): clong {.
    importc: "BIO_callback_ctrl", header: "openssl/evp.h".}
proc BIO_ptr_ctrl*(bp: ptr BIO; cmd: cint; larg: clong): cstring {.
    importc: "BIO_ptr_ctrl", header: "openssl/evp.h".}
proc BIO_int_ctrl*(bp: ptr BIO; cmd: cint; larg: clong; iarg: cint): clong {.
    importc: "BIO_int_ctrl", header: "openssl/evp.h".}
proc BIO_push*(b: ptr BIO; append: ptr BIO): ptr BIO {.importc: "BIO_push", 
    header: "openssl/evp.h".}
proc BIO_pop*(b: ptr BIO): ptr BIO {.importc: "BIO_pop", header: "openssl/evp.h".}
proc BIO_free_all*(a: ptr BIO) {.importc: "BIO_free_all", 
                                 header: "openssl/evp.h".}
proc BIO_find_type*(b: ptr BIO; bio_type: cint): ptr BIO {.
    importc: "BIO_find_type", header: "openssl/evp.h".}
proc BIO_next*(b: ptr BIO): ptr BIO {.importc: "BIO_next", 
                                      header: "openssl/evp.h".}
proc BIO_get_retry_BIO*(bio: ptr BIO; reason: ptr cint): ptr BIO {.
    importc: "BIO_get_retry_BIO", header: "openssl/evp.h".}
proc BIO_get_retry_reason*(bio: ptr BIO): cint {.
    importc: "BIO_get_retry_reason", header: "openssl/evp.h".}
proc BIO_dup_chain*(input: ptr BIO): ptr BIO {.importc: "BIO_dup_chain", 
    header: "openssl/evp.h".}
proc BIO_nread0*(bio: ptr BIO; buf: cstringArray): cint {.importc: "BIO_nread0", 
    header: "openssl/evp.h".}
proc BIO_nread*(bio: ptr BIO; buf: cstringArray; num: cint): cint {.
    importc: "BIO_nread", header: "openssl/evp.h".}
proc BIO_nwrite0*(bio: ptr BIO; buf: cstringArray): cint {.
    importc: "BIO_nwrite0", header: "openssl/evp.h".}
proc BIO_nwrite*(bio: ptr BIO; buf: cstringArray; num: cint): cint {.
    importc: "BIO_nwrite", header: "openssl/evp.h".}
proc BIO_debug_callback*(bio: ptr BIO; cmd: cint; argp: cstring; argi: cint; 
                         argl: clong; ret: clong): clong {.
    importc: "BIO_debug_callback", header: "openssl/evp.h".}
proc BIO_s_mem*(): ptr BIO_METHOD {.importc: "BIO_s_mem", 
                                    header: "openssl/evp.h".}
proc BIO_new_mem_buf*(buf: pointer; len: cint): ptr BIO {.
    importc: "BIO_new_mem_buf", header: "openssl/evp.h".}
proc BIO_s_socket*(): ptr BIO_METHOD {.importc: "BIO_s_socket", 
                                       header: "openssl/evp.h".}
proc BIO_s_connect*(): ptr BIO_METHOD {.importc: "BIO_s_connect", 
                                        header: "openssl/evp.h".}
proc BIO_s_accept*(): ptr BIO_METHOD {.importc: "BIO_s_accept", 
                                       header: "openssl/evp.h".}
proc BIO_s_fd*(): ptr BIO_METHOD {.importc: "BIO_s_fd", header: "openssl/evp.h".}
proc BIO_s_log*(): ptr BIO_METHOD {.importc: "BIO_s_log", 
                                    header: "openssl/evp.h".}
proc BIO_s_bio*(): ptr BIO_METHOD {.importc: "BIO_s_bio", 
                                    header: "openssl/evp.h".}
proc BIO_s_null*(): ptr BIO_METHOD {.importc: "BIO_s_null", 
                                     header: "openssl/evp.h".}
proc BIO_f_null*(): ptr BIO_METHOD {.importc: "BIO_f_null", 
                                     header: "openssl/evp.h".}
proc BIO_f_buffer*(): ptr BIO_METHOD {.importc: "BIO_f_buffer", 
                                       header: "openssl/evp.h".}
proc BIO_f_nbio_test*(): ptr BIO_METHOD {.importc: "BIO_f_nbio_test", 
    header: "openssl/evp.h".}
proc BIO_s_datagram*(): ptr BIO_METHOD {.importc: "BIO_s_datagram", 
    header: "openssl/evp.h".}
proc BIO_sock_should_retry*(i: cint): cint {.importc: "BIO_sock_should_retry", 
    header: "openssl/evp.h".}
proc BIO_sock_non_fatal_error*(error: cint): cint {.
    importc: "BIO_sock_non_fatal_error", header: "openssl/evp.h".}
proc BIO_dgram_non_fatal_error*(error: cint): cint {.
    importc: "BIO_dgram_non_fatal_error", header: "openssl/evp.h".}
proc BIO_fd_should_retry*(i: cint): cint {.importc: "BIO_fd_should_retry", 
    header: "openssl/evp.h".}
proc BIO_fd_non_fatal_error*(error: cint): cint {.
    importc: "BIO_fd_non_fatal_error", header: "openssl/evp.h".}
proc BIO_dump_cb*(cb: proc (data: pointer; len: csize; u: pointer): cint; 
                  u: pointer; s: cstring; len: cint): cint {.
    importc: "BIO_dump_cb", header: "openssl/evp.h".}
proc BIO_dump_indent_cb*(cb: proc (data: pointer; len: csize; u: pointer): cint; 
                         u: pointer; s: cstring; len: cint; indent: cint): cint {.
    importc: "BIO_dump_indent_cb", header: "openssl/evp.h".}
proc BIO_dump*(b: ptr BIO; bytes: cstring; len: cint): cint {.
    importc: "BIO_dump", header: "openssl/evp.h".}
proc BIO_dump_indent*(b: ptr BIO; bytes: cstring; len: cint; indent: cint): cint {.
    importc: "BIO_dump_indent", header: "openssl/evp.h".}
proc BIO_dump_fp*(fp: ptr FILE; s: cstring; len: cint): cint {.
    importc: "BIO_dump_fp", header: "openssl/evp.h".}
proc BIO_dump_indent_fp*(fp: ptr FILE; s: cstring; len: cint; indent: cint): cint {.
    importc: "BIO_dump_indent_fp", header: "openssl/evp.h".}
proc BIO_gethostbyname*(name: cstring): ptr hostent {.
    importc: "BIO_gethostbyname", header: "openssl/evp.h".}
proc BIO_sock_error*(sock: cint): cint {.importc: "BIO_sock_error", 
    header: "openssl/evp.h".}
proc BIO_socket_ioctl*(fd: cint; typ: clong; arg: pointer): cint {.
    importc: "BIO_socket_ioctl", header: "openssl/evp.h".}
proc BIO_socket_nbio*(fd: cint; mode: cint): cint {.importc: "BIO_socket_nbio", 
    header: "openssl/evp.h".}
proc BIO_get_port*(str: cstring; port_ptr: ptr cushort): cint {.
    importc: "BIO_get_port", header: "openssl/evp.h".}
proc BIO_get_host_ip*(str: cstring; ip: ptr cuchar): cint {.
    importc: "BIO_get_host_ip", header: "openssl/evp.h".}
proc BIO_get_accept_socket*(host_port: cstring; mode: cint): cint {.
    importc: "BIO_get_accept_socket", header: "openssl/evp.h".}
proc BIO_accept*(sock: cint; ip_port: cstringArray): cint {.
    importc: "BIO_accept", header: "openssl/evp.h".}
proc BIO_sock_init*(): cint {.importc: "BIO_sock_init", header: "openssl/evp.h".}
proc BIO_sock_cleanup*() {.importc: "BIO_sock_cleanup", header: "openssl/evp.h".}
proc BIO_set_tcp_ndelay*(sock: cint; turn_on: cint): cint {.
    importc: "BIO_set_tcp_ndelay", header: "openssl/evp.h".}
proc BIO_new_socket*(sock: cint; close_flag: cint): ptr BIO {.
    importc: "BIO_new_socket", header: "openssl/evp.h".}
proc BIO_new_dgram*(fd: cint; close_flag: cint): ptr BIO {.
    importc: "BIO_new_dgram", header: "openssl/evp.h".}
proc BIO_new_fd*(fd: cint; close_flag: cint): ptr BIO {.importc: "BIO_new_fd", 
    header: "openssl/evp.h".}
proc BIO_new_connect*(host_port: cstring): ptr BIO {.importc: "BIO_new_connect", 
    header: "openssl/evp.h".}
proc BIO_new_accept*(host_port: cstring): ptr BIO {.importc: "BIO_new_accept", 
    header: "openssl/evp.h".}
proc BIO_new_bio_pair*(bio1: ptr ptr BIO; writebuf1: csize; bio2: ptr ptr BIO; 
                       writebuf2: csize): cint {.importc: "BIO_new_bio_pair", 
    header: "openssl/evp.h".}
proc BIO_copy_next_retry*(b: ptr BIO) {.importc: "BIO_copy_next_retry", 
                                        header: "openssl/evp.h".}
#int BIO_printf(BIO *bio, const char *format, ...)
# __attribute__((__format__(__printf__,2,3)));
#int BIO_vprintf(BIO *bio, const char *format, va_list args)
# __attribute__((__format__(__printf__,2,0)));
#int BIO_snprintf(char *buf, size_t n, const char *format, ...)
# __attribute__((__format__(__printf__,3,4)));
#int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
# __attribute__((__format__(__printf__,3,0)));

proc ERR_load_BIO_strings*() {.importc: "ERR_load_BIO_strings", 
                               header: "openssl/evp.h".}
type 
  bignum_st* {.importc: "bignum_st", header: "openssl/evp.h".} = object 
    d* {.importc: "d".}: ptr culong
    top* {.importc: "top".}: cint
    dmax* {.importc: "dmax".}: cint
    neg* {.importc: "neg".}: cint
    flags* {.importc: "flags".}: cint

  bn_mont_ctx_st* {.importc: "bn_mont_ctx_st", header: "openssl/evp.h".} = object 
    ri* {.importc: "ri".}: cint
    RR* {.importc: "RR".}: BIGNUM
    N* {.importc: "N".}: BIGNUM
    Ni* {.importc: "Ni".}: BIGNUM
    n0* {.importc: "n0".}: array[2, culong]
    flags* {.importc: "flags".}: cint

  bn_recp_ctx_st* {.importc: "bn_recp_ctx_st", header: "openssl/evp.h".} = object 
    N* {.importc: "N".}: BIGNUM
    Nr* {.importc: "Nr".}: BIGNUM
    num_bits* {.importc: "num_bits".}: cint
    shift* {.importc: "shift".}: cint
    flags* {.importc: "flags".}: cint

  INNER_C_UNION_7037465089661267053* {.importc: "no_name", 
                                       header: "openssl/evp.h".} = object  {.
      union.}
    cb_1* {.importc: "cb_1".}: proc (a2: cint; a3: cint; a4: pointer)
    cb_2* {.importc: "cb_2".}: proc (a2: cint; a3: cint; a4: ptr BN_GENCB): cint

  bn_gencb_st* {.importc: "bn_gencb_st", header: "openssl/evp.h".} = object 
    ver* {.importc: "ver".}: cuint
    arg* {.importc: "arg".}: pointer
    cb* {.importc: "cb".}: INNER_C_UNION_7037465089661267053


proc BN_GENCB_call*(cb: ptr BN_GENCB; a: cint; b: cint): cint {.
    importc: "BN_GENCB_call", header: "openssl/evp.h".}
proc BN_value_one*(): ptr BIGNUM {.importc: "BN_value_one", 
                                   header: "openssl/evp.h".}
proc BN_options*(): cstring {.importc: "BN_options", header: "openssl/evp.h".}
proc BN_CTX_new*(): ptr BN_CTX {.importc: "BN_CTX_new", header: "openssl/evp.h".}
proc BN_CTX_init*(c: ptr BN_CTX) {.importc: "BN_CTX_init", 
                                   header: "openssl/evp.h".}
proc BN_CTX_free*(c: ptr BN_CTX) {.importc: "BN_CTX_free", 
                                   header: "openssl/evp.h".}
proc BN_CTX_start*(ctx: ptr BN_CTX) {.importc: "BN_CTX_start", 
                                      header: "openssl/evp.h".}
proc BN_CTX_get*(ctx: ptr BN_CTX): ptr BIGNUM {.importc: "BN_CTX_get", 
    header: "openssl/evp.h".}
proc BN_CTX_end*(ctx: ptr BN_CTX) {.importc: "BN_CTX_end", 
                                    header: "openssl/evp.h".}
proc BN_rand*(rnd: ptr BIGNUM; bits: cint; top: cint; bottom: cint): cint {.
    importc: "BN_rand", header: "openssl/evp.h".}
proc BN_pseudo_rand*(rnd: ptr BIGNUM; bits: cint; top: cint; bottom: cint): cint {.
    importc: "BN_pseudo_rand", header: "openssl/evp.h".}
proc BN_rand_range*(rnd: ptr BIGNUM; range: ptr BIGNUM): cint {.
    importc: "BN_rand_range", header: "openssl/evp.h".}
proc BN_pseudo_rand_range*(rnd: ptr BIGNUM; range: ptr BIGNUM): cint {.
    importc: "BN_pseudo_rand_range", header: "openssl/evp.h".}
proc BN_num_bits*(a: ptr BIGNUM): cint {.importc: "BN_num_bits", 
    header: "openssl/evp.h".}
proc BN_num_bits_word*(a2: culong): cint {.importc: "BN_num_bits_word", 
    header: "openssl/evp.h".}
proc BN_new*(): ptr BIGNUM {.importc: "BN_new", header: "openssl/evp.h".}
proc BN_init*(a2: ptr BIGNUM) {.importc: "BN_init", header: "openssl/evp.h".}
proc BN_clear_free*(a: ptr BIGNUM) {.importc: "BN_clear_free", 
                                     header: "openssl/evp.h".}
proc BN_copy*(a: ptr BIGNUM; b: ptr BIGNUM): ptr BIGNUM {.importc: "BN_copy", 
    header: "openssl/evp.h".}
proc BN_swap*(a: ptr BIGNUM; b: ptr BIGNUM) {.importc: "BN_swap", 
    header: "openssl/evp.h".}
proc BN_bin2bn*(s: ptr cuchar; len: cint; ret: ptr BIGNUM): ptr BIGNUM {.
    importc: "BN_bin2bn", header: "openssl/evp.h".}
proc BN_bn2bin*(a: ptr BIGNUM; to: ptr cuchar): cint {.importc: "BN_bn2bin", 
    header: "openssl/evp.h".}
proc BN_mpi2bn*(s: ptr cuchar; len: cint; ret: ptr BIGNUM): ptr BIGNUM {.
    importc: "BN_mpi2bn", header: "openssl/evp.h".}
proc BN_bn2mpi*(a: ptr BIGNUM; to: ptr cuchar): cint {.importc: "BN_bn2mpi", 
    header: "openssl/evp.h".}
proc BN_sub*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.
    importc: "BN_sub", header: "openssl/evp.h".}
proc BN_usub*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.
    importc: "BN_usub", header: "openssl/evp.h".}
proc BN_uadd*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.
    importc: "BN_uadd", header: "openssl/evp.h".}
proc BN_add*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.
    importc: "BN_add", header: "openssl/evp.h".}
proc BN_mul*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_mul", header: "openssl/evp.h".}
proc BN_sqr*(r: ptr BIGNUM; a: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_sqr", header: "openssl/evp.h".}
proc BN_set_negative*(b: ptr BIGNUM; n: cint) {.importc: "BN_set_negative", 
    header: "openssl/evp.h".}
proc BN_div*(dv: ptr BIGNUM; rem: ptr BIGNUM; m: ptr BIGNUM; d: ptr BIGNUM; 
             ctx: ptr BN_CTX): cint {.importc: "BN_div", header: "openssl/evp.h".}
proc BN_nnmod*(r: ptr BIGNUM; m: ptr BIGNUM; d: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_nnmod", header: "openssl/evp.h".}
proc BN_mod_add*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; m: ptr BIGNUM; 
                 ctx: ptr BN_CTX): cint {.importc: "BN_mod_add", 
    header: "openssl/evp.h".}
proc BN_mod_add_quick*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                       m: ptr BIGNUM): cint {.importc: "BN_mod_add_quick", 
    header: "openssl/evp.h".}
proc BN_mod_sub*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; m: ptr BIGNUM; 
                 ctx: ptr BN_CTX): cint {.importc: "BN_mod_sub", 
    header: "openssl/evp.h".}
proc BN_mod_sub_quick*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                       m: ptr BIGNUM): cint {.importc: "BN_mod_sub_quick", 
    header: "openssl/evp.h".}
proc BN_mod_mul*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; m: ptr BIGNUM; 
                 ctx: ptr BN_CTX): cint {.importc: "BN_mod_mul", 
    header: "openssl/evp.h".}
proc BN_mod_sqr*(r: ptr BIGNUM; a: ptr BIGNUM; m: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_mod_sqr", header: "openssl/evp.h".}
proc BN_mod_lshift1*(r: ptr BIGNUM; a: ptr BIGNUM; m: ptr BIGNUM; 
                     ctx: ptr BN_CTX): cint {.importc: "BN_mod_lshift1", 
    header: "openssl/evp.h".}
proc BN_mod_lshift1_quick*(r: ptr BIGNUM; a: ptr BIGNUM; m: ptr BIGNUM): cint {.
    importc: "BN_mod_lshift1_quick", header: "openssl/evp.h".}
proc BN_mod_lshift*(r: ptr BIGNUM; a: ptr BIGNUM; n: cint; m: ptr BIGNUM; 
                    ctx: ptr BN_CTX): cint {.importc: "BN_mod_lshift", 
    header: "openssl/evp.h".}
proc BN_mod_lshift_quick*(r: ptr BIGNUM; a: ptr BIGNUM; n: cint; m: ptr BIGNUM): cint {.
    importc: "BN_mod_lshift_quick", header: "openssl/evp.h".}
proc BN_mod_word*(a: ptr BIGNUM; w: culong): culong {.importc: "BN_mod_word", 
    header: "openssl/evp.h".}
proc BN_div_word*(a: ptr BIGNUM; w: culong): culong {.importc: "BN_div_word", 
    header: "openssl/evp.h".}
proc BN_mul_word*(a: ptr BIGNUM; w: culong): cint {.importc: "BN_mul_word", 
    header: "openssl/evp.h".}
proc BN_add_word*(a: ptr BIGNUM; w: culong): cint {.importc: "BN_add_word", 
    header: "openssl/evp.h".}
proc BN_sub_word*(a: ptr BIGNUM; w: culong): cint {.importc: "BN_sub_word", 
    header: "openssl/evp.h".}
proc BN_set_word*(a: ptr BIGNUM; w: culong): cint {.importc: "BN_set_word", 
    header: "openssl/evp.h".}
proc BN_get_word*(a: ptr BIGNUM): culong {.importc: "BN_get_word", 
    header: "openssl/evp.h".}
proc BN_cmp*(a: ptr BIGNUM; b: ptr BIGNUM): cint {.importc: "BN_cmp", 
    header: "openssl/evp.h".}
proc BN_free*(a: ptr BIGNUM) {.importc: "BN_free", header: "openssl/evp.h".}
proc BN_is_bit_set*(a: ptr BIGNUM; n: cint): cint {.importc: "BN_is_bit_set", 
    header: "openssl/evp.h".}
proc BN_lshift*(r: ptr BIGNUM; a: ptr BIGNUM; n: cint): cint {.
    importc: "BN_lshift", header: "openssl/evp.h".}
proc BN_lshift1*(r: ptr BIGNUM; a: ptr BIGNUM): cint {.importc: "BN_lshift1", 
    header: "openssl/evp.h".}
proc BN_exp*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_exp", header: "openssl/evp.h".}
proc BN_mod_exp*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; m: ptr BIGNUM; 
                 ctx: ptr BN_CTX): cint {.importc: "BN_mod_exp", 
    header: "openssl/evp.h".}
proc BN_mod_exp_mont*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      m: ptr BIGNUM; ctx: ptr BN_CTX; m_ctx: ptr BN_MONT_CTX): cint {.
    importc: "BN_mod_exp_mont", header: "openssl/evp.h".}
proc BN_mod_exp_mont_consttime*(rr: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                                m: ptr BIGNUM; ctx: ptr BN_CTX; 
                                in_mont: ptr BN_MONT_CTX): cint {.
    importc: "BN_mod_exp_mont_consttime", header: "openssl/evp.h".}
proc BN_mod_exp_mont_word*(r: ptr BIGNUM; a: culong; p: ptr BIGNUM; 
                           m: ptr BIGNUM; ctx: ptr BN_CTX; 
                           m_ctx: ptr BN_MONT_CTX): cint {.
    importc: "BN_mod_exp_mont_word", header: "openssl/evp.h".}
proc BN_mod_exp2_mont*(r: ptr BIGNUM; a1: ptr BIGNUM; p1: ptr BIGNUM; 
                       a2: ptr BIGNUM; p2: ptr BIGNUM; m: ptr BIGNUM; 
                       ctx: ptr BN_CTX; m_ctx: ptr BN_MONT_CTX): cint {.
    importc: "BN_mod_exp2_mont", header: "openssl/evp.h".}
proc BN_mod_exp_simple*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                        m: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_mod_exp_simple", header: "openssl/evp.h".}
proc BN_mask_bits*(a: ptr BIGNUM; n: cint): cint {.importc: "BN_mask_bits", 
    header: "openssl/evp.h".}
proc BN_print_fp*(fp: ptr FILE; a: ptr BIGNUM): cint {.importc: "BN_print_fp", 
    header: "openssl/evp.h".}
proc BN_print*(fp: ptr BIO; a: ptr BIGNUM): cint {.importc: "BN_print", 
    header: "openssl/evp.h".}
proc BN_reciprocal*(r: ptr BIGNUM; m: ptr BIGNUM; len: cint; ctx: ptr BN_CTX): cint {.
    importc: "BN_reciprocal", header: "openssl/evp.h".}
proc BN_rshift*(r: ptr BIGNUM; a: ptr BIGNUM; n: cint): cint {.
    importc: "BN_rshift", header: "openssl/evp.h".}
proc BN_rshift1*(r: ptr BIGNUM; a: ptr BIGNUM): cint {.importc: "BN_rshift1", 
    header: "openssl/evp.h".}
proc BN_clear*(a: ptr BIGNUM) {.importc: "BN_clear", header: "openssl/evp.h".}
proc BN_dup*(a: ptr BIGNUM): ptr BIGNUM {.importc: "BN_dup", 
    header: "openssl/evp.h".}
proc BN_ucmp*(a: ptr BIGNUM; b: ptr BIGNUM): cint {.importc: "BN_ucmp", 
    header: "openssl/evp.h".}
proc BN_set_bit*(a: ptr BIGNUM; n: cint): cint {.importc: "BN_set_bit", 
    header: "openssl/evp.h".}
proc BN_clear_bit*(a: ptr BIGNUM; n: cint): cint {.importc: "BN_clear_bit", 
    header: "openssl/evp.h".}
proc BN_bn2hex*(a: ptr BIGNUM): cstring {.importc: "BN_bn2hex", 
    header: "openssl/evp.h".}
proc BN_bn2dec*(a: ptr BIGNUM): cstring {.importc: "BN_bn2dec", 
    header: "openssl/evp.h".}
proc BN_hex2bn*(a: ptr ptr BIGNUM; str: cstring): cint {.importc: "BN_hex2bn", 
    header: "openssl/evp.h".}
proc BN_dec2bn*(a: ptr ptr BIGNUM; str: cstring): cint {.importc: "BN_dec2bn", 
    header: "openssl/evp.h".}
proc BN_asc2bn*(a: ptr ptr BIGNUM; str: cstring): cint {.importc: "BN_asc2bn", 
    header: "openssl/evp.h".}
proc BN_gcd*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_gcd", header: "openssl/evp.h".}
proc BN_kronecker*(a: ptr BIGNUM; b: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_kronecker", header: "openssl/evp.h".}
proc BN_mod_inverse*(ret: ptr BIGNUM; a: ptr BIGNUM; n: ptr BIGNUM; 
                     ctx: ptr BN_CTX): ptr BIGNUM {.importc: "BN_mod_inverse", 
    header: "openssl/evp.h".}
proc BN_mod_sqrt*(ret: ptr BIGNUM; a: ptr BIGNUM; n: ptr BIGNUM; ctx: ptr BN_CTX): ptr BIGNUM {.
    importc: "BN_mod_sqrt", header: "openssl/evp.h".}
proc BN_consttime_swap*(swap: culong; a: ptr BIGNUM; b: ptr BIGNUM; nwords: cint) {.
    importc: "BN_consttime_swap", header: "openssl/evp.h".}
proc BN_generate_prime*(ret: ptr BIGNUM; bits: cint; safe: cint; 
                        add: ptr BIGNUM; rem: ptr BIGNUM; 
                        callback: proc (a2: cint; a3: cint; a4: pointer); 
                        cb_arg: pointer): ptr BIGNUM {.
    importc: "BN_generate_prime", header: "openssl/evp.h".}
proc BN_is_prime*(p: ptr BIGNUM; nchecks: cint; 
                  callback: proc (a2: cint; a3: cint; a4: pointer); 
                  ctx: ptr BN_CTX; cb_arg: pointer): cint {.
    importc: "BN_is_prime", header: "openssl/evp.h".}
proc BN_is_prime_fasttest*(p: ptr BIGNUM; nchecks: cint; 
                           callback: proc (a2: cint; a3: cint; a4: pointer); 
                           ctx: ptr BN_CTX; cb_arg: pointer; 
                           do_trial_division: cint): cint {.
    importc: "BN_is_prime_fasttest", header: "openssl/evp.h".}
proc BN_generate_prime_ex*(ret: ptr BIGNUM; bits: cint; safe: cint; 
                           add: ptr BIGNUM; rem: ptr BIGNUM; cb: ptr BN_GENCB): cint {.
    importc: "BN_generate_prime_ex", header: "openssl/evp.h".}
proc BN_is_prime_ex*(p: ptr BIGNUM; nchecks: cint; ctx: ptr BN_CTX; 
                     cb: ptr BN_GENCB): cint {.importc: "BN_is_prime_ex", 
    header: "openssl/evp.h".}
proc BN_is_prime_fasttest_ex*(p: ptr BIGNUM; nchecks: cint; ctx: ptr BN_CTX; 
                              do_trial_division: cint; cb: ptr BN_GENCB): cint {.
    importc: "BN_is_prime_fasttest_ex", header: "openssl/evp.h".}
proc BN_X931_generate_Xpq*(Xp: ptr BIGNUM; Xq: ptr BIGNUM; nbits: cint; 
                           ctx: ptr BN_CTX): cint {.
    importc: "BN_X931_generate_Xpq", header: "openssl/evp.h".}
proc BN_X931_derive_prime_ex*(p: ptr BIGNUM; p1: ptr BIGNUM; p2: ptr BIGNUM; 
                              Xp: ptr BIGNUM; Xp1: ptr BIGNUM; Xp2: ptr BIGNUM; 
                              e: ptr BIGNUM; ctx: ptr BN_CTX; cb: ptr BN_GENCB): cint {.
    importc: "BN_X931_derive_prime_ex", header: "openssl/evp.h".}
proc BN_X931_generate_prime_ex*(p: ptr BIGNUM; p1: ptr BIGNUM; p2: ptr BIGNUM; 
                                Xp1: ptr BIGNUM; Xp2: ptr BIGNUM; 
                                Xp: ptr BIGNUM; e: ptr BIGNUM; ctx: ptr BN_CTX; 
                                cb: ptr BN_GENCB): cint {.
    importc: "BN_X931_generate_prime_ex", header: "openssl/evp.h".}
proc BN_MONT_CTX_new*(): ptr BN_MONT_CTX {.importc: "BN_MONT_CTX_new", 
    header: "openssl/evp.h".}
proc BN_MONT_CTX_init*(ctx: ptr BN_MONT_CTX) {.importc: "BN_MONT_CTX_init", 
    header: "openssl/evp.h".}
proc BN_mod_mul_montgomery*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                            mont: ptr BN_MONT_CTX; ctx: ptr BN_CTX): cint {.
    importc: "BN_mod_mul_montgomery", header: "openssl/evp.h".}
proc BN_from_montgomery*(r: ptr BIGNUM; a: ptr BIGNUM; mont: ptr BN_MONT_CTX; 
                         ctx: ptr BN_CTX): cint {.importc: "BN_from_montgomery", 
    header: "openssl/evp.h".}
proc BN_MONT_CTX_free*(mont: ptr BN_MONT_CTX) {.importc: "BN_MONT_CTX_free", 
    header: "openssl/evp.h".}
proc BN_MONT_CTX_set*(mont: ptr BN_MONT_CTX; mod: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_MONT_CTX_set", header: "openssl/evp.h".}
proc BN_MONT_CTX_copy*(to: ptr BN_MONT_CTX; frm: ptr BN_MONT_CTX): ptr BN_MONT_CTX {.
    importc: "BN_MONT_CTX_copy", header: "openssl/evp.h".}
proc BN_MONT_CTX_set_locked*(pmont: ptr ptr BN_MONT_CTX; lock: cint; 
                             mod: ptr BIGNUM; ctx: ptr BN_CTX): ptr BN_MONT_CTX {.
    importc: "BN_MONT_CTX_set_locked", header: "openssl/evp.h".}
proc BN_BLINDING_new*(A: ptr BIGNUM; Ai: ptr BIGNUM; mod: ptr BIGNUM): ptr BN_BLINDING {.
    importc: "BN_BLINDING_new", header: "openssl/evp.h".}
proc BN_BLINDING_free*(b: ptr BN_BLINDING) {.importc: "BN_BLINDING_free", 
    header: "openssl/evp.h".}
proc BN_BLINDING_update*(b: ptr BN_BLINDING; ctx: ptr BN_CTX): cint {.
    importc: "BN_BLINDING_update", header: "openssl/evp.h".}
proc BN_BLINDING_convert*(n: ptr BIGNUM; b: ptr BN_BLINDING; ctx: ptr BN_CTX): cint {.
    importc: "BN_BLINDING_convert", header: "openssl/evp.h".}
proc BN_BLINDING_invert*(n: ptr BIGNUM; b: ptr BN_BLINDING; ctx: ptr BN_CTX): cint {.
    importc: "BN_BLINDING_invert", header: "openssl/evp.h".}
proc BN_BLINDING_convert_ex*(n: ptr BIGNUM; r: ptr BIGNUM; b: ptr BN_BLINDING; 
                             a5: ptr BN_CTX): cint {.
    importc: "BN_BLINDING_convert_ex", header: "openssl/evp.h".}
proc BN_BLINDING_invert_ex*(n: ptr BIGNUM; r: ptr BIGNUM; b: ptr BN_BLINDING; 
                            a5: ptr BN_CTX): cint {.
    importc: "BN_BLINDING_invert_ex", header: "openssl/evp.h".}
proc BN_BLINDING_get_thread_id*(a2: ptr BN_BLINDING): culong {.
    importc: "BN_BLINDING_get_thread_id", header: "openssl/evp.h".}
proc BN_BLINDING_set_thread_id*(a2: ptr BN_BLINDING; a3: culong) {.
    importc: "BN_BLINDING_set_thread_id", header: "openssl/evp.h".}
proc BN_BLINDING_thread_id*(a2: ptr BN_BLINDING): ptr CRYPTO_THREADID {.
    importc: "BN_BLINDING_thread_id", header: "openssl/evp.h".}
proc BN_BLINDING_get_flags*(a2: ptr BN_BLINDING): culong {.
    importc: "BN_BLINDING_get_flags", header: "openssl/evp.h".}
proc BN_BLINDING_set_flags*(a2: ptr BN_BLINDING; a3: culong) {.
    importc: "BN_BLINDING_set_flags", header: "openssl/evp.h".}
proc BN_BLINDING_create_param*(b: ptr BN_BLINDING; e: ptr BIGNUM; m: ptr BIGNUM; 
                               ctx: ptr BN_CTX; bn_mod_exp: proc (r: ptr BIGNUM; 
    a: ptr BIGNUM; p: ptr BIGNUM; m: ptr BIGNUM; ctx: ptr BN_CTX; 
    m_ctx: ptr BN_MONT_CTX): cint; m_ctx: ptr BN_MONT_CTX): ptr BN_BLINDING {.
    importc: "BN_BLINDING_create_param", header: "openssl/evp.h".}
proc BN_set_params*(mul: cint; high: cint; low: cint; mont: cint) {.
    importc: "BN_set_params", header: "openssl/evp.h".}
proc BN_get_params*(which: cint): cint {.importc: "BN_get_params", 
    header: "openssl/evp.h".}
proc BN_RECP_CTX_init*(recp: ptr BN_RECP_CTX) {.importc: "BN_RECP_CTX_init", 
    header: "openssl/evp.h".}
proc BN_RECP_CTX_new*(): ptr BN_RECP_CTX {.importc: "BN_RECP_CTX_new", 
    header: "openssl/evp.h".}
proc BN_RECP_CTX_free*(recp: ptr BN_RECP_CTX) {.importc: "BN_RECP_CTX_free", 
    header: "openssl/evp.h".}
proc BN_RECP_CTX_set*(recp: ptr BN_RECP_CTX; rdiv: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_RECP_CTX_set", header: "openssl/evp.h".}
proc BN_mod_mul_reciprocal*(r: ptr BIGNUM; x: ptr BIGNUM; y: ptr BIGNUM; 
                            recp: ptr BN_RECP_CTX; ctx: ptr BN_CTX): cint {.
    importc: "BN_mod_mul_reciprocal", header: "openssl/evp.h".}
proc BN_mod_exp_recp*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      m: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_mod_exp_recp", header: "openssl/evp.h".}
proc BN_div_recp*(dv: ptr BIGNUM; rem: ptr BIGNUM; m: ptr BIGNUM; 
                  recp: ptr BN_RECP_CTX; ctx: ptr BN_CTX): cint {.
    importc: "BN_div_recp", header: "openssl/evp.h".}
proc BN_GF2m_add*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM): cint {.
    importc: "BN_GF2m_add", header: "openssl/evp.h".}
proc BN_GF2m_mod*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM): cint {.
    importc: "BN_GF2m_mod", header: "openssl/evp.h".}
proc BN_GF2m_mod_mul*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                      p: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_mul", header: "openssl/evp.h".}
proc BN_GF2m_mod_sqr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.importc: "BN_GF2m_mod_sqr", 
    header: "openssl/evp.h".}
proc BN_GF2m_mod_inv*(r: ptr BIGNUM; b: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.importc: "BN_GF2m_mod_inv", 
    header: "openssl/evp.h".}
proc BN_GF2m_mod_div*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                      p: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_div", header: "openssl/evp.h".}
proc BN_GF2m_mod_exp*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                      p: ptr BIGNUM; ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_exp", header: "openssl/evp.h".}
proc BN_GF2m_mod_sqrt*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                       ctx: ptr BN_CTX): cint {.importc: "BN_GF2m_mod_sqrt", 
    header: "openssl/evp.h".}
proc BN_GF2m_mod_solve_quad*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                             ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_solve_quad", header: "openssl/evp.h".}
proc BN_GF2m_mod_arr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr cint): cint {.
    importc: "BN_GF2m_mod_arr", header: "openssl/evp.h".}
proc BN_GF2m_mod_mul_arr*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                          p: ptr cint; ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_mul_arr", header: "openssl/evp.h".}
proc BN_GF2m_mod_sqr_arr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr cint; 
                          ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_sqr_arr", header: "openssl/evp.h".}
proc BN_GF2m_mod_inv_arr*(r: ptr BIGNUM; b: ptr BIGNUM; p: ptr cint; 
                          ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_inv_arr", header: "openssl/evp.h".}
proc BN_GF2m_mod_div_arr*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                          p: ptr cint; ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_div_arr", header: "openssl/evp.h".}
proc BN_GF2m_mod_exp_arr*(r: ptr BIGNUM; a: ptr BIGNUM; b: ptr BIGNUM; 
                          p: ptr cint; ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_exp_arr", header: "openssl/evp.h".}
proc BN_GF2m_mod_sqrt_arr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr cint; 
                           ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_sqrt_arr", header: "openssl/evp.h".}
proc BN_GF2m_mod_solve_quad_arr*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr cint; 
                                 ctx: ptr BN_CTX): cint {.
    importc: "BN_GF2m_mod_solve_quad_arr", header: "openssl/evp.h".}
proc BN_GF2m_poly2arr*(a: ptr BIGNUM; p: ptr cint; max: cint): cint {.
    importc: "BN_GF2m_poly2arr", header: "openssl/evp.h".}
proc BN_GF2m_arr2poly*(p: ptr cint; a: ptr BIGNUM): cint {.
    importc: "BN_GF2m_arr2poly", header: "openssl/evp.h".}
proc BN_nist_mod_192*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.importc: "BN_nist_mod_192", 
    header: "openssl/evp.h".}
proc BN_nist_mod_224*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.importc: "BN_nist_mod_224", 
    header: "openssl/evp.h".}
proc BN_nist_mod_256*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.importc: "BN_nist_mod_256", 
    header: "openssl/evp.h".}
proc BN_nist_mod_384*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.importc: "BN_nist_mod_384", 
    header: "openssl/evp.h".}
proc BN_nist_mod_521*(r: ptr BIGNUM; a: ptr BIGNUM; p: ptr BIGNUM; 
                      ctx: ptr BN_CTX): cint {.importc: "BN_nist_mod_521", 
    header: "openssl/evp.h".}
proc BN_get0_nist_prime_192*(): ptr BIGNUM {.importc: "BN_get0_nist_prime_192", 
    header: "openssl/evp.h".}
proc BN_get0_nist_prime_224*(): ptr BIGNUM {.importc: "BN_get0_nist_prime_224", 
    header: "openssl/evp.h".}
proc BN_get0_nist_prime_256*(): ptr BIGNUM {.importc: "BN_get0_nist_prime_256", 
    header: "openssl/evp.h".}
proc BN_get0_nist_prime_384*(): ptr BIGNUM {.importc: "BN_get0_nist_prime_384", 
    header: "openssl/evp.h".}
proc BN_get0_nist_prime_521*(): ptr BIGNUM {.importc: "BN_get0_nist_prime_521", 
    header: "openssl/evp.h".}
proc bn_expand2*(a: ptr BIGNUM; words: cint): ptr BIGNUM {.
    importc: "bn_expand2", header: "openssl/evp.h".}
proc bn_dup_expand*(a: ptr BIGNUM; words: cint): ptr BIGNUM {.
    importc: "bn_dup_expand", header: "openssl/evp.h".}
proc bn_mul_add_words*(rp: ptr culong; ap: ptr culong; num: cint; w: culong): culong {.
    importc: "bn_mul_add_words", header: "openssl/evp.h".}
proc bn_mul_words*(rp: ptr culong; ap: ptr culong; num: cint; w: culong): culong {.
    importc: "bn_mul_words", header: "openssl/evp.h".}
proc bn_sqr_words*(rp: ptr culong; ap: ptr culong; num: cint) {.
    importc: "bn_sqr_words", header: "openssl/evp.h".}
proc bn_div_words*(h: culong; l: culong; d: culong): culong {.
    importc: "bn_div_words", header: "openssl/evp.h".}
proc bn_add_words*(rp: ptr culong; ap: ptr culong; bp: ptr culong; num: cint): culong {.
    importc: "bn_add_words", header: "openssl/evp.h".}
proc bn_sub_words*(rp: ptr culong; ap: ptr culong; bp: ptr culong; num: cint): culong {.
    importc: "bn_sub_words", header: "openssl/evp.h".}
proc get_rfc2409_prime_768*(bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "get_rfc2409_prime_768", header: "openssl/evp.h".}
proc get_rfc2409_prime_1024*(bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "get_rfc2409_prime_1024", header: "openssl/evp.h".}
proc get_rfc3526_prime_1536*(bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "get_rfc3526_prime_1536", header: "openssl/evp.h".}
proc get_rfc3526_prime_2048*(bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "get_rfc3526_prime_2048", header: "openssl/evp.h".}
proc get_rfc3526_prime_3072*(bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "get_rfc3526_prime_3072", header: "openssl/evp.h".}
proc get_rfc3526_prime_4096*(bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "get_rfc3526_prime_4096", header: "openssl/evp.h".}
proc get_rfc3526_prime_6144*(bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "get_rfc3526_prime_6144", header: "openssl/evp.h".}
proc get_rfc3526_prime_8192*(bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "get_rfc3526_prime_8192", header: "openssl/evp.h".}
proc BN_bntest_rand*(rnd: ptr BIGNUM; bits: cint; top: cint; bottom: cint): cint {.
    importc: "BN_bntest_rand", header: "openssl/evp.h".}
proc ERR_load_BN_strings*() {.importc: "ERR_load_BN_strings", 
                              header: "openssl/evp.h".}
type 
  X509_algor_st* {.importc: "X509_algor_st", header: "openssl/evp.h".} = object 
  
  stack_st_X509_ALGOR* {.importc: "stack_st_X509_ALGOR", header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  ASN1_CTX* {.importc: "ASN1_CTX", header: "openssl/evp.h".} = object 
    p* {.importc: "p".}: ptr cuchar
    eos* {.importc: "eos".}: cint
    error* {.importc: "error".}: cint
    inf* {.importc: "inf".}: cint
    tag* {.importc: "tag".}: cint
    xclass* {.importc: "xclass".}: cint
    slen* {.importc: "slen".}: clong
    max* {.importc: "max".}: ptr cuchar
    q* {.importc: "q".}: ptr cuchar
    pp* {.importc: "pp".}: ptr ptr cuchar
    line* {.importc: "line".}: cint

  ASN1_const_CTX* {.importc: "ASN1_const_CTX", header: "openssl/evp.h".} = object 
    p* {.importc: "p".}: ptr cuchar
    eos* {.importc: "eos".}: cint
    error* {.importc: "error".}: cint
    inf* {.importc: "inf".}: cint
    tag* {.importc: "tag".}: cint
    xclass* {.importc: "xclass".}: cint
    slen* {.importc: "slen".}: clong
    max* {.importc: "max".}: ptr cuchar
    q* {.importc: "q".}: ptr cuchar
    pp* {.importc: "pp".}: ptr ptr cuchar
    line* {.importc: "line".}: cint

  ASN1_OBJECT* {.importc: "ASN1_OBJECT", header: "openssl/evp.h".} = object 
    sn* {.importc: "sn".}: cstring
    ln* {.importc: "ln".}: cstring
    nid* {.importc: "nid".}: cint
    length* {.importc: "length".}: cint
    data* {.importc: "data".}: ptr cuchar
    flags* {.importc: "flags".}: cint

  asn1_string_st* {.importc: "asn1_string_st", header: "openssl/evp.h".} = object 
    length* {.importc: "length".}: cint
    typ* {.importc: "type".}: cint
    data* {.importc: "data".}: ptr cuchar
    flags* {.importc: "flags".}: clong

  ASN1_ENCODING* {.importc: "ASN1_ENCODING", header: "openssl/evp.h".} = object 
    enc* {.importc: "enc".}: ptr cuchar
    len* {.importc: "len".}: clong
    modified* {.importc: "modified".}: cint

  ASN1_STRING_TABLE* {.importc: "ASN1_STRING_TABLE", header: "openssl/evp.h".} = object 
    nid* {.importc: "nid".}: cint
    minsize* {.importc: "minsize".}: clong
    maxsize* {.importc: "maxsize".}: clong
    mask* {.importc: "mask".}: culong
    flags* {.importc: "flags".}: culong

  stack_st_ASN1_STRING_TABLE* {.importc: "stack_st_ASN1_STRING_TABLE", 
                                header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  ASN1_TEMPLATE* = ASN1_TEMPLATE_st
  ASN1_TLC* = ASN1_TLC_st
  ASN1_VALUE* = ASN1_VALUE_st
  d2i_of_void* = proc (a2: ptr pointer; a3: ptr ptr cuchar; a4: clong): pointer
  i2d_of_void* = proc (a2: pointer; a3: ptr ptr cuchar): cint
  ASN1_ITEM_EXP* = ASN1_ITEM
  stack_st_ASN1_INTEGER* {.importc: "stack_st_ASN1_INTEGER", 
                           header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  stack_st_ASN1_GENERALSTRING* {.importc: "stack_st_ASN1_GENERALSTRING", 
                                 header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  INNER_C_UNION_6985933777976061847* {.importc: "no_name", 
                                       header: "openssl/evp.h".} = object  {.
      union.}
    pntr* {.importc: "ptr".}: cstring
    boolean* {.importc: "boolean".}: ASN1_BOOLEAN
    asn1_string* {.importc: "asn1_string".}: ptr ASN1_STRING
    object* {.importc: "object".}: ptr ASN1_OBJECT
    integer* {.importc: "integer".}: ptr ASN1_INTEGER
    enumerated* {.importc: "enumerated".}: ptr ASN1_ENUMERATED
    bit_string* {.importc: "bit_string".}: ptr ASN1_BIT_STRING
    octet_string* {.importc: "octet_string".}: ptr ASN1_OCTET_STRING
    printablestring* {.importc: "printablestring".}: ptr ASN1_PRINTABLESTRING
    t61string* {.importc: "t61string".}: ptr ASN1_T61STRING
    ia5string* {.importc: "ia5string".}: ptr ASN1_IA5STRING
    generalstring* {.importc: "generalstring".}: ptr ASN1_GENERALSTRING
    bmpstring* {.importc: "bmpstring".}: ptr ASN1_BMPSTRING
    universalstring* {.importc: "universalstring".}: ptr ASN1_UNIVERSALSTRING
    utctime* {.importc: "utctime".}: ptr ASN1_UTCTIME
    generalizedtime* {.importc: "generalizedtime".}: ptr ASN1_GENERALIZEDTIME
    visiblestring* {.importc: "visiblestring".}: ptr ASN1_VISIBLESTRING
    utf8string* {.importc: "utf8string".}: ptr ASN1_UTF8STRING
    set* {.importc: "set".}: ptr ASN1_STRING
    sequence* {.importc: "sequence".}: ptr ASN1_STRING
    asn1_value* {.importc: "asn1_value".}: ptr ASN1_VALUE

  ASN1_TYPE* {.importc: "ASN1_TYPE", header: "openssl/evp.h".} = object 
    typ* {.importc: "type".}: cint
    value* {.importc: "value".}: INNER_C_UNION_6985933777976061847

  stack_st_ASN1_TYPE* {.importc: "stack_st_ASN1_TYPE", header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack

  ASN1_SEQUENCE_ANY* = stack_st_ASN1_TYPE

proc d2i_ASN1_SEQUENCE_ANY*(a: ptr ptr ASN1_SEQUENCE_ANY; input: ptr ptr cuchar; 
                            len: clong): ptr ASN1_SEQUENCE_ANY {.
    importc: "d2i_ASN1_SEQUENCE_ANY", header: "openssl/evp.h".}
proc i2d_ASN1_SEQUENCE_ANY*(a: ptr ASN1_SEQUENCE_ANY; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_SEQUENCE_ANY", header: "openssl/evp.h".}
var ASN1_SEQUENCE_ANY_it* {.importc: "ASN1_SEQUENCE_ANY_it", 
                            header: "openssl/evp.h".}: ASN1_ITEM

proc d2i_ASN1_SET_ANY*(a: ptr ptr ASN1_SEQUENCE_ANY; input: ptr ptr cuchar; 
                       len: clong): ptr ASN1_SEQUENCE_ANY {.
    importc: "d2i_ASN1_SET_ANY", header: "openssl/evp.h".}
proc i2d_ASN1_SET_ANY*(a: ptr ASN1_SEQUENCE_ANY; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_SET_ANY", header: "openssl/evp.h".}
var ASN1_SET_ANY_it* {.importc: "ASN1_SET_ANY_it", header: "openssl/evp.h".}: ASN1_ITEM

type 
  NETSCAPE_X509* {.importc: "NETSCAPE_X509", header: "openssl/evp.h".} = object 
    header* {.importc: "header".}: ptr ASN1_OCTET_STRING
    cert* {.importc: "cert".}: ptr X509

  BIT_STRING_BITNAME* {.importc: "BIT_STRING_BITNAME", header: "openssl/evp.h".} = object 
    bitnum* {.importc: "bitnum".}: cint
    lname* {.importc: "lname".}: cstring
    sname* {.importc: "sname".}: cstring


proc ASN1_TYPE_new*(): ptr ASN1_TYPE {.importc: "ASN1_TYPE_new", 
                                       header: "openssl/evp.h".}
proc ASN1_TYPE_free*(a: ptr ASN1_TYPE) {.importc: "ASN1_TYPE_free", 
    header: "openssl/evp.h".}
proc d2i_ASN1_TYPE*(a: ptr ptr ASN1_TYPE; input: ptr ptr cuchar; len: clong): ptr ASN1_TYPE {.
    importc: "d2i_ASN1_TYPE", header: "openssl/evp.h".}
proc i2d_ASN1_TYPE*(a: ptr ASN1_TYPE; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_TYPE", header: "openssl/evp.h".}
var ASN1_ANY_it* {.importc: "ASN1_ANY_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_TYPE_get*(a: ptr ASN1_TYPE): cint {.importc: "ASN1_TYPE_get", 
    header: "openssl/evp.h".}
proc ASN1_TYPE_set*(a: ptr ASN1_TYPE; typ: cint; value: pointer) {.
    importc: "ASN1_TYPE_set", header: "openssl/evp.h".}
proc ASN1_TYPE_set1*(a: ptr ASN1_TYPE; typ: cint; value: pointer): cint {.
    importc: "ASN1_TYPE_set1", header: "openssl/evp.h".}
proc ASN1_TYPE_cmp*(a: ptr ASN1_TYPE; b: ptr ASN1_TYPE): cint {.
    importc: "ASN1_TYPE_cmp", header: "openssl/evp.h".}
proc ASN1_OBJECT_new*(): ptr ASN1_OBJECT {.importc: "ASN1_OBJECT_new", 
    header: "openssl/evp.h".}
proc ASN1_OBJECT_free*(a: ptr ASN1_OBJECT) {.importc: "ASN1_OBJECT_free", 
    header: "openssl/evp.h".}
proc i2d_ASN1_OBJECT*(a: ptr ASN1_OBJECT; pp: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_OBJECT", header: "openssl/evp.h".}
proc c2i_ASN1_OBJECT*(a: ptr ptr ASN1_OBJECT; pp: ptr ptr cuchar; length: clong): ptr ASN1_OBJECT {.
    importc: "c2i_ASN1_OBJECT", header: "openssl/evp.h".}
proc d2i_ASN1_OBJECT*(a: ptr ptr ASN1_OBJECT; pp: ptr ptr cuchar; length: clong): ptr ASN1_OBJECT {.
    importc: "d2i_ASN1_OBJECT", header: "openssl/evp.h".}
var ASN1_OBJECT_it* {.importc: "ASN1_OBJECT_it", header: "openssl/evp.h".}: ASN1_ITEM

type 
  stack_st_ASN1_OBJECT* {.importc: "stack_st_ASN1_OBJECT", 
                          header: "openssl/evp.h".} = object 
    stack* {.importc: "stack".}: mStack


proc ASN1_STRING_new*(): ptr ASN1_STRING {.importc: "ASN1_STRING_new", 
    header: "openssl/evp.h".}
proc ASN1_STRING_free*(a: ptr ASN1_STRING) {.importc: "ASN1_STRING_free", 
    header: "openssl/evp.h".}
proc ASN1_STRING_copy*(dst: ptr ASN1_STRING; str: ptr ASN1_STRING): cint {.
    importc: "ASN1_STRING_copy", header: "openssl/evp.h".}
proc ASN1_STRING_dup*(a: ptr ASN1_STRING): ptr ASN1_STRING {.
    importc: "ASN1_STRING_dup", header: "openssl/evp.h".}
proc ASN1_STRING_type_new*(typ: cint): ptr ASN1_STRING {.
    importc: "ASN1_STRING_type_new", header: "openssl/evp.h".}
proc ASN1_STRING_cmp*(a: ptr ASN1_STRING; b: ptr ASN1_STRING): cint {.
    importc: "ASN1_STRING_cmp", header: "openssl/evp.h".}
proc ASN1_STRING_set*(str: ptr ASN1_STRING; data: pointer; len: cint): cint {.
    importc: "ASN1_STRING_set", header: "openssl/evp.h".}
proc ASN1_STRING_set0*(str: ptr ASN1_STRING; data: pointer; len: cint) {.
    importc: "ASN1_STRING_set0", header: "openssl/evp.h".}
proc ASN1_STRING_length*(x: ptr ASN1_STRING): cint {.
    importc: "ASN1_STRING_length", header: "openssl/evp.h".}
proc ASN1_STRING_length_set*(x: ptr ASN1_STRING; n: cint) {.
    importc: "ASN1_STRING_length_set", header: "openssl/evp.h".}
proc ASN1_STRING_type*(x: ptr ASN1_STRING): cint {.importc: "ASN1_STRING_type", 
    header: "openssl/evp.h".}
proc ASN1_STRING_data*(x: ptr ASN1_STRING): ptr cuchar {.
    importc: "ASN1_STRING_data", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_new*(): ptr ASN1_BIT_STRING {.
    importc: "ASN1_BIT_STRING_new", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_free*(a: ptr ASN1_BIT_STRING) {.
    importc: "ASN1_BIT_STRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_BIT_STRING*(a: ptr ptr ASN1_BIT_STRING; input: ptr ptr cuchar; 
                          len: clong): ptr ASN1_BIT_STRING {.
    importc: "d2i_ASN1_BIT_STRING", header: "openssl/evp.h".}
proc i2d_ASN1_BIT_STRING*(a: ptr ASN1_BIT_STRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_BIT_STRING", header: "openssl/evp.h".}
var ASN1_BIT_STRING_it* {.importc: "ASN1_BIT_STRING_it", header: "openssl/evp.h".}: ASN1_ITEM

proc i2c_ASN1_BIT_STRING*(a: ptr ASN1_BIT_STRING; pp: ptr ptr cuchar): cint {.
    importc: "i2c_ASN1_BIT_STRING", header: "openssl/evp.h".}
proc c2i_ASN1_BIT_STRING*(a: ptr ptr ASN1_BIT_STRING; pp: ptr ptr cuchar; 
                          length: clong): ptr ASN1_BIT_STRING {.
    importc: "c2i_ASN1_BIT_STRING", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_set*(a: ptr ASN1_BIT_STRING; d: ptr cuchar; length: cint): cint {.
    importc: "ASN1_BIT_STRING_set", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_set_bit*(a: ptr ASN1_BIT_STRING; n: cint; value: cint): cint {.
    importc: "ASN1_BIT_STRING_set_bit", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_get_bit*(a: ptr ASN1_BIT_STRING; n: cint): cint {.
    importc: "ASN1_BIT_STRING_get_bit", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_check*(a: ptr ASN1_BIT_STRING; flags: ptr cuchar; 
                            flags_len: cint): cint {.
    importc: "ASN1_BIT_STRING_check", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_name_print*(output: ptr BIO; bs: ptr ASN1_BIT_STRING; 
                                 tbl: ptr BIT_STRING_BITNAME; indent: cint): cint {.
    importc: "ASN1_BIT_STRING_name_print", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_num_asc*(name: cstring; tbl: ptr BIT_STRING_BITNAME): cint {.
    importc: "ASN1_BIT_STRING_num_asc", header: "openssl/evp.h".}
proc ASN1_BIT_STRING_set_asc*(bs: ptr ASN1_BIT_STRING; name: cstring; 
                              value: cint; tbl: ptr BIT_STRING_BITNAME): cint {.
    importc: "ASN1_BIT_STRING_set_asc", header: "openssl/evp.h".}
proc i2d_ASN1_BOOLEAN*(a: cint; pp: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_BOOLEAN", header: "openssl/evp.h".}
proc d2i_ASN1_BOOLEAN*(a: ptr cint; pp: ptr ptr cuchar; length: clong): cint {.
    importc: "d2i_ASN1_BOOLEAN", header: "openssl/evp.h".}
proc ASN1_INTEGER_new*(): ptr ASN1_INTEGER {.importc: "ASN1_INTEGER_new", 
    header: "openssl/evp.h".}
proc ASN1_INTEGER_free*(a: ptr ASN1_INTEGER) {.importc: "ASN1_INTEGER_free", 
    header: "openssl/evp.h".}
proc d2i_ASN1_INTEGER*(a: ptr ptr ASN1_INTEGER; input: ptr ptr cuchar; 
                       len: clong): ptr ASN1_INTEGER {.
    importc: "d2i_ASN1_INTEGER", header: "openssl/evp.h".}
proc i2d_ASN1_INTEGER*(a: ptr ASN1_INTEGER; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_INTEGER", header: "openssl/evp.h".}
var ASN1_INTEGER_it* {.importc: "ASN1_INTEGER_it", header: "openssl/evp.h".}: ASN1_ITEM

proc i2c_ASN1_INTEGER*(a: ptr ASN1_INTEGER; pp: ptr ptr cuchar): cint {.
    importc: "i2c_ASN1_INTEGER", header: "openssl/evp.h".}
proc c2i_ASN1_INTEGER*(a: ptr ptr ASN1_INTEGER; pp: ptr ptr cuchar; 
                       length: clong): ptr ASN1_INTEGER {.
    importc: "c2i_ASN1_INTEGER", header: "openssl/evp.h".}
proc d2i_ASN1_UINTEGER*(a: ptr ptr ASN1_INTEGER; pp: ptr ptr cuchar; 
                        length: clong): ptr ASN1_INTEGER {.
    importc: "d2i_ASN1_UINTEGER", header: "openssl/evp.h".}
proc ASN1_INTEGER_dup*(x: ptr ASN1_INTEGER): ptr ASN1_INTEGER {.
    importc: "ASN1_INTEGER_dup", header: "openssl/evp.h".}
proc ASN1_INTEGER_cmp*(x: ptr ASN1_INTEGER; y: ptr ASN1_INTEGER): cint {.
    importc: "ASN1_INTEGER_cmp", header: "openssl/evp.h".}
proc ASN1_ENUMERATED_new*(): ptr ASN1_ENUMERATED {.
    importc: "ASN1_ENUMERATED_new", header: "openssl/evp.h".}
proc ASN1_ENUMERATED_free*(a: ptr ASN1_ENUMERATED) {.
    importc: "ASN1_ENUMERATED_free", header: "openssl/evp.h".}
proc d2i_ASN1_ENUMERATED*(a: ptr ptr ASN1_ENUMERATED; input: ptr ptr cuchar; 
                          len: clong): ptr ASN1_ENUMERATED {.
    importc: "d2i_ASN1_ENUMERATED", header: "openssl/evp.h".}
proc i2d_ASN1_ENUMERATED*(a: ptr ASN1_ENUMERATED; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_ENUMERATED", header: "openssl/evp.h".}
var ASN1_ENUMERATED_it* {.importc: "ASN1_ENUMERATED_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_UTCTIME_check*(a: ptr ASN1_UTCTIME): cint {.
    importc: "ASN1_UTCTIME_check", header: "openssl/evp.h".}
proc ASN1_UTCTIME_set*(s: ptr ASN1_UTCTIME; t: time_t): ptr ASN1_UTCTIME {.
    importc: "ASN1_UTCTIME_set", header: "openssl/evp.h".}
proc ASN1_UTCTIME_adj*(s: ptr ASN1_UTCTIME; t: time_t; offset_day: cint; 
                       offset_sec: clong): ptr ASN1_UTCTIME {.
    importc: "ASN1_UTCTIME_adj", header: "openssl/evp.h".}
proc ASN1_UTCTIME_set_string*(s: ptr ASN1_UTCTIME; str: cstring): cint {.
    importc: "ASN1_UTCTIME_set_string", header: "openssl/evp.h".}
proc ASN1_UTCTIME_cmp_time_t*(s: ptr ASN1_UTCTIME; t: time_t): cint {.
    importc: "ASN1_UTCTIME_cmp_time_t", header: "openssl/evp.h".}
proc ASN1_GENERALIZEDTIME_check*(a: ptr ASN1_GENERALIZEDTIME): cint {.
    importc: "ASN1_GENERALIZEDTIME_check", header: "openssl/evp.h".}
proc ASN1_GENERALIZEDTIME_set*(s: ptr ASN1_GENERALIZEDTIME; t: time_t): ptr ASN1_GENERALIZEDTIME {.
    importc: "ASN1_GENERALIZEDTIME_set", header: "openssl/evp.h".}
proc ASN1_GENERALIZEDTIME_adj*(s: ptr ASN1_GENERALIZEDTIME; t: time_t; 
                               offset_day: cint; offset_sec: clong): ptr ASN1_GENERALIZEDTIME {.
    importc: "ASN1_GENERALIZEDTIME_adj", header: "openssl/evp.h".}
proc ASN1_GENERALIZEDTIME_set_string*(s: ptr ASN1_GENERALIZEDTIME; str: cstring): cint {.
    importc: "ASN1_GENERALIZEDTIME_set_string", header: "openssl/evp.h".}
proc ASN1_OCTET_STRING_new*(): ptr ASN1_OCTET_STRING {.
    importc: "ASN1_OCTET_STRING_new", header: "openssl/evp.h".}
proc ASN1_OCTET_STRING_free*(a: ptr ASN1_OCTET_STRING) {.
    importc: "ASN1_OCTET_STRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_OCTET_STRING*(a: ptr ptr ASN1_OCTET_STRING; input: ptr ptr cuchar; 
                            len: clong): ptr ASN1_OCTET_STRING {.
    importc: "d2i_ASN1_OCTET_STRING", header: "openssl/evp.h".}
proc i2d_ASN1_OCTET_STRING*(a: ptr ASN1_OCTET_STRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_OCTET_STRING", header: "openssl/evp.h".}
var ASN1_OCTET_STRING_it* {.importc: "ASN1_OCTET_STRING_it", 
                            header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_OCTET_STRING_dup*(a: ptr ASN1_OCTET_STRING): ptr ASN1_OCTET_STRING {.
    importc: "ASN1_OCTET_STRING_dup", header: "openssl/evp.h".}
proc ASN1_OCTET_STRING_cmp*(a: ptr ASN1_OCTET_STRING; b: ptr ASN1_OCTET_STRING): cint {.
    importc: "ASN1_OCTET_STRING_cmp", header: "openssl/evp.h".}
proc ASN1_OCTET_STRING_set*(str: ptr ASN1_OCTET_STRING; data: ptr cuchar; 
                            len: cint): cint {.importc: "ASN1_OCTET_STRING_set", 
    header: "openssl/evp.h".}
proc ASN1_VISIBLESTRING_new*(): ptr ASN1_VISIBLESTRING {.
    importc: "ASN1_VISIBLESTRING_new", header: "openssl/evp.h".}
proc ASN1_VISIBLESTRING_free*(a: ptr ASN1_VISIBLESTRING) {.
    importc: "ASN1_VISIBLESTRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_VISIBLESTRING*(a: ptr ptr ASN1_VISIBLESTRING; 
                             input: ptr ptr cuchar; len: clong): ptr ASN1_VISIBLESTRING {.
    importc: "d2i_ASN1_VISIBLESTRING", header: "openssl/evp.h".}
proc i2d_ASN1_VISIBLESTRING*(a: ptr ASN1_VISIBLESTRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_VISIBLESTRING", header: "openssl/evp.h".}
var ASN1_VISIBLESTRING_it* {.importc: "ASN1_VISIBLESTRING_it", 
                             header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_UNIVERSALSTRING_new*(): ptr ASN1_UNIVERSALSTRING {.
    importc: "ASN1_UNIVERSALSTRING_new", header: "openssl/evp.h".}
proc ASN1_UNIVERSALSTRING_free*(a: ptr ASN1_UNIVERSALSTRING) {.
    importc: "ASN1_UNIVERSALSTRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_UNIVERSALSTRING*(a: ptr ptr ASN1_UNIVERSALSTRING; 
                               input: ptr ptr cuchar; len: clong): ptr ASN1_UNIVERSALSTRING {.
    importc: "d2i_ASN1_UNIVERSALSTRING", header: "openssl/evp.h".}
proc i2d_ASN1_UNIVERSALSTRING*(a: ptr ASN1_UNIVERSALSTRING; 
                               output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_UNIVERSALSTRING", header: "openssl/evp.h".}
var ASN1_UNIVERSALSTRING_it* {.importc: "ASN1_UNIVERSALSTRING_it", 
                               header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_UTF8STRING_new*(): ptr ASN1_UTF8STRING {.
    importc: "ASN1_UTF8STRING_new", header: "openssl/evp.h".}
proc ASN1_UTF8STRING_free*(a: ptr ASN1_UTF8STRING) {.
    importc: "ASN1_UTF8STRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_UTF8STRING*(a: ptr ptr ASN1_UTF8STRING; input: ptr ptr cuchar; 
                          len: clong): ptr ASN1_UTF8STRING {.
    importc: "d2i_ASN1_UTF8STRING", header: "openssl/evp.h".}
proc i2d_ASN1_UTF8STRING*(a: ptr ASN1_UTF8STRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_UTF8STRING", header: "openssl/evp.h".}
var ASN1_UTF8STRING_it* {.importc: "ASN1_UTF8STRING_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_NULL_new*(): ptr ASN1_NULL {.importc: "ASN1_NULL_new", 
                                       header: "openssl/evp.h".}
proc ASN1_NULL_free*(a: ptr ASN1_NULL) {.importc: "ASN1_NULL_free", 
    header: "openssl/evp.h".}
proc d2i_ASN1_NULL*(a: ptr ptr ASN1_NULL; input: ptr ptr cuchar; len: clong): ptr ASN1_NULL {.
    importc: "d2i_ASN1_NULL", header: "openssl/evp.h".}
proc i2d_ASN1_NULL*(a: ptr ASN1_NULL; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_NULL", header: "openssl/evp.h".}
var ASN1_NULL_it* {.importc: "ASN1_NULL_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_BMPSTRING_new*(): ptr ASN1_BMPSTRING {.importc: "ASN1_BMPSTRING_new", 
    header: "openssl/evp.h".}
proc ASN1_BMPSTRING_free*(a: ptr ASN1_BMPSTRING) {.
    importc: "ASN1_BMPSTRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_BMPSTRING*(a: ptr ptr ASN1_BMPSTRING; input: ptr ptr cuchar; 
                         len: clong): ptr ASN1_BMPSTRING {.
    importc: "d2i_ASN1_BMPSTRING", header: "openssl/evp.h".}
proc i2d_ASN1_BMPSTRING*(a: ptr ASN1_BMPSTRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_BMPSTRING", header: "openssl/evp.h".}
var ASN1_BMPSTRING_it* {.importc: "ASN1_BMPSTRING_it", header: "openssl/evp.h".}: ASN1_ITEM

proc UTF8_getc*(str: ptr cuchar; len: cint; val: ptr culong): cint {.
    importc: "UTF8_getc", header: "openssl/evp.h".}
proc UTF8_putc*(str: ptr cuchar; len: cint; value: culong): cint {.
    importc: "UTF8_putc", header: "openssl/evp.h".}
proc ASN1_PRINTABLE_new*(): ptr ASN1_STRING {.importc: "ASN1_PRINTABLE_new", 
    header: "openssl/evp.h".}
proc ASN1_PRINTABLE_free*(a: ptr ASN1_STRING) {.importc: "ASN1_PRINTABLE_free", 
    header: "openssl/evp.h".}
proc d2i_ASN1_PRINTABLE*(a: ptr ptr ASN1_STRING; input: ptr ptr cuchar; 
                         len: clong): ptr ASN1_STRING {.
    importc: "d2i_ASN1_PRINTABLE", header: "openssl/evp.h".}
proc i2d_ASN1_PRINTABLE*(a: ptr ASN1_STRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_PRINTABLE", header: "openssl/evp.h".}
var ASN1_PRINTABLE_it* {.importc: "ASN1_PRINTABLE_it", header: "openssl/evp.h".}: ASN1_ITEM

proc DIRECTORYSTRING_new*(): ptr ASN1_STRING {.importc: "DIRECTORYSTRING_new", 
    header: "openssl/evp.h".}
proc DIRECTORYSTRING_free*(a: ptr ASN1_STRING) {.
    importc: "DIRECTORYSTRING_free", header: "openssl/evp.h".}
proc d2i_DIRECTORYSTRING*(a: ptr ptr ASN1_STRING; input: ptr ptr cuchar; 
                          len: clong): ptr ASN1_STRING {.
    importc: "d2i_DIRECTORYSTRING", header: "openssl/evp.h".}
proc i2d_DIRECTORYSTRING*(a: ptr ASN1_STRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_DIRECTORYSTRING", header: "openssl/evp.h".}
var DIRECTORYSTRING_it* {.importc: "DIRECTORYSTRING_it", header: "openssl/evp.h".}: ASN1_ITEM

proc DISPLAYTEXT_new*(): ptr ASN1_STRING {.importc: "DISPLAYTEXT_new", 
    header: "openssl/evp.h".}
proc DISPLAYTEXT_free*(a: ptr ASN1_STRING) {.importc: "DISPLAYTEXT_free", 
    header: "openssl/evp.h".}
proc d2i_DISPLAYTEXT*(a: ptr ptr ASN1_STRING; input: ptr ptr cuchar; len: clong): ptr ASN1_STRING {.
    importc: "d2i_DISPLAYTEXT", header: "openssl/evp.h".}
proc i2d_DISPLAYTEXT*(a: ptr ASN1_STRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_DISPLAYTEXT", header: "openssl/evp.h".}
var DISPLAYTEXT_it* {.importc: "DISPLAYTEXT_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_PRINTABLESTRING_new*(): ptr ASN1_PRINTABLESTRING {.
    importc: "ASN1_PRINTABLESTRING_new", header: "openssl/evp.h".}
proc ASN1_PRINTABLESTRING_free*(a: ptr ASN1_PRINTABLESTRING) {.
    importc: "ASN1_PRINTABLESTRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_PRINTABLESTRING*(a: ptr ptr ASN1_PRINTABLESTRING; 
                               input: ptr ptr cuchar; len: clong): ptr ASN1_PRINTABLESTRING {.
    importc: "d2i_ASN1_PRINTABLESTRING", header: "openssl/evp.h".}
proc i2d_ASN1_PRINTABLESTRING*(a: ptr ASN1_PRINTABLESTRING; 
                               output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_PRINTABLESTRING", header: "openssl/evp.h".}
var ASN1_PRINTABLESTRING_it* {.importc: "ASN1_PRINTABLESTRING_it", 
                               header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_T61STRING_new*(): ptr ASN1_T61STRING {.importc: "ASN1_T61STRING_new", 
    header: "openssl/evp.h".}
proc ASN1_T61STRING_free*(a: ptr ASN1_T61STRING) {.
    importc: "ASN1_T61STRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_T61STRING*(a: ptr ptr ASN1_T61STRING; input: ptr ptr cuchar; 
                         len: clong): ptr ASN1_T61STRING {.
    importc: "d2i_ASN1_T61STRING", header: "openssl/evp.h".}
proc i2d_ASN1_T61STRING*(a: ptr ASN1_T61STRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_T61STRING", header: "openssl/evp.h".}
var ASN1_T61STRING_it* {.importc: "ASN1_T61STRING_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_IA5STRING_new*(): ptr ASN1_IA5STRING {.importc: "ASN1_IA5STRING_new", 
    header: "openssl/evp.h".}
proc ASN1_IA5STRING_free*(a: ptr ASN1_IA5STRING) {.
    importc: "ASN1_IA5STRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_IA5STRING*(a: ptr ptr ASN1_IA5STRING; input: ptr ptr cuchar; 
                         len: clong): ptr ASN1_IA5STRING {.
    importc: "d2i_ASN1_IA5STRING", header: "openssl/evp.h".}
proc i2d_ASN1_IA5STRING*(a: ptr ASN1_IA5STRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_IA5STRING", header: "openssl/evp.h".}
var ASN1_IA5STRING_it* {.importc: "ASN1_IA5STRING_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_GENERALSTRING_new*(): ptr ASN1_GENERALSTRING {.
    importc: "ASN1_GENERALSTRING_new", header: "openssl/evp.h".}
proc ASN1_GENERALSTRING_free*(a: ptr ASN1_GENERALSTRING) {.
    importc: "ASN1_GENERALSTRING_free", header: "openssl/evp.h".}
proc d2i_ASN1_GENERALSTRING*(a: ptr ptr ASN1_GENERALSTRING; 
                             input: ptr ptr cuchar; len: clong): ptr ASN1_GENERALSTRING {.
    importc: "d2i_ASN1_GENERALSTRING", header: "openssl/evp.h".}
proc i2d_ASN1_GENERALSTRING*(a: ptr ASN1_GENERALSTRING; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_GENERALSTRING", header: "openssl/evp.h".}
var ASN1_GENERALSTRING_it* {.importc: "ASN1_GENERALSTRING_it", 
                             header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_UTCTIME_new*(): ptr ASN1_UTCTIME {.importc: "ASN1_UTCTIME_new", 
    header: "openssl/evp.h".}
proc ASN1_UTCTIME_free*(a: ptr ASN1_UTCTIME) {.importc: "ASN1_UTCTIME_free", 
    header: "openssl/evp.h".}
proc d2i_ASN1_UTCTIME*(a: ptr ptr ASN1_UTCTIME; input: ptr ptr cuchar; 
                       len: clong): ptr ASN1_UTCTIME {.
    importc: "d2i_ASN1_UTCTIME", header: "openssl/evp.h".}
proc i2d_ASN1_UTCTIME*(a: ptr ASN1_UTCTIME; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_UTCTIME", header: "openssl/evp.h".}
var ASN1_UTCTIME_it* {.importc: "ASN1_UTCTIME_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_GENERALIZEDTIME_new*(): ptr ASN1_GENERALIZEDTIME {.
    importc: "ASN1_GENERALIZEDTIME_new", header: "openssl/evp.h".}
proc ASN1_GENERALIZEDTIME_free*(a: ptr ASN1_GENERALIZEDTIME) {.
    importc: "ASN1_GENERALIZEDTIME_free", header: "openssl/evp.h".}
proc d2i_ASN1_GENERALIZEDTIME*(a: ptr ptr ASN1_GENERALIZEDTIME; 
                               input: ptr ptr cuchar; len: clong): ptr ASN1_GENERALIZEDTIME {.
    importc: "d2i_ASN1_GENERALIZEDTIME", header: "openssl/evp.h".}
proc i2d_ASN1_GENERALIZEDTIME*(a: ptr ASN1_GENERALIZEDTIME; 
                               output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_GENERALIZEDTIME", header: "openssl/evp.h".}
var ASN1_GENERALIZEDTIME_it* {.importc: "ASN1_GENERALIZEDTIME_it", 
                               header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_TIME_new*(): ptr ASN1_TIME {.importc: "ASN1_TIME_new", 
                                       header: "openssl/evp.h".}
proc ASN1_TIME_free*(a: ptr ASN1_TIME) {.importc: "ASN1_TIME_free", 
    header: "openssl/evp.h".}
proc d2i_ASN1_TIME*(a: ptr ptr ASN1_TIME; input: ptr ptr cuchar; len: clong): ptr ASN1_TIME {.
    importc: "d2i_ASN1_TIME", header: "openssl/evp.h".}
proc i2d_ASN1_TIME*(a: ptr ASN1_TIME; output: ptr ptr cuchar): cint {.
    importc: "i2d_ASN1_TIME", header: "openssl/evp.h".}
var ASN1_TIME_it* {.importc: "ASN1_TIME_it", header: "openssl/evp.h".}: ASN1_ITEM

var ASN1_OCTET_STRING_NDEF_it* {.importc: "ASN1_OCTET_STRING_NDEF_it", 
                                 header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_TIME_set*(s: ptr ASN1_TIME; t: time_t): ptr ASN1_TIME {.
    importc: "ASN1_TIME_set", header: "openssl/evp.h".}
proc ASN1_TIME_adj*(s: ptr ASN1_TIME; t: time_t; offset_day: cint; 
                    offset_sec: clong): ptr ASN1_TIME {.
    importc: "ASN1_TIME_adj", header: "openssl/evp.h".}
proc ASN1_TIME_check*(t: ptr ASN1_TIME): cint {.importc: "ASN1_TIME_check", 
    header: "openssl/evp.h".}
proc ASN1_TIME_to_generalizedtime*(t: ptr ASN1_TIME; 
                                   output: ptr ptr ASN1_GENERALIZEDTIME): ptr ASN1_GENERALIZEDTIME {.
    importc: "ASN1_TIME_to_generalizedtime", header: "openssl/evp.h".}
proc ASN1_TIME_set_string*(s: ptr ASN1_TIME; str: cstring): cint {.
    importc: "ASN1_TIME_set_string", header: "openssl/evp.h".}
proc i2d_ASN1_SET*(a: ptr stack_st_OPENSSL_BLOCK; pp: ptr ptr cuchar; 
                   i2d: ptr i2d_of_void; ex_tag: cint; ex_class: cint; 
                   is_set: cint): cint {.importc: "i2d_ASN1_SET", 
    header: "openssl/evp.h".}
proc d2i_ASN1_SET*(a: ptr ptr stack_st_OPENSSL_BLOCK; pp: ptr ptr cuchar; 
                   length: clong; d2i: ptr d2i_of_void; 
                   free_func: proc (a2: OPENSSL_BLOCK); ex_tag: cint; 
                   ex_class: cint): ptr stack_st_OPENSSL_BLOCK {.
    importc: "d2i_ASN1_SET", header: "openssl/evp.h".}
proc i2a_ASN1_INTEGER*(bp: ptr BIO; a: ptr ASN1_INTEGER): cint {.
    importc: "i2a_ASN1_INTEGER", header: "openssl/evp.h".}
proc a2i_ASN1_INTEGER*(bp: ptr BIO; bs: ptr ASN1_INTEGER; buf: cstring; 
                       size: cint): cint {.importc: "a2i_ASN1_INTEGER", 
    header: "openssl/evp.h".}
proc i2a_ASN1_ENUMERATED*(bp: ptr BIO; a: ptr ASN1_ENUMERATED): cint {.
    importc: "i2a_ASN1_ENUMERATED", header: "openssl/evp.h".}
proc a2i_ASN1_ENUMERATED*(bp: ptr BIO; bs: ptr ASN1_ENUMERATED; buf: cstring; 
                          size: cint): cint {.importc: "a2i_ASN1_ENUMERATED", 
    header: "openssl/evp.h".}
proc i2a_ASN1_OBJECT*(bp: ptr BIO; a: ptr ASN1_OBJECT): cint {.
    importc: "i2a_ASN1_OBJECT", header: "openssl/evp.h".}
proc a2i_ASN1_STRING*(bp: ptr BIO; bs: ptr ASN1_STRING; buf: cstring; size: cint): cint {.
    importc: "a2i_ASN1_STRING", header: "openssl/evp.h".}
proc i2a_ASN1_STRING*(bp: ptr BIO; a: ptr ASN1_STRING; typ: cint): cint {.
    importc: "i2a_ASN1_STRING", header: "openssl/evp.h".}
proc i2t_ASN1_OBJECT*(buf: cstring; buf_len: cint; a: ptr ASN1_OBJECT): cint {.
    importc: "i2t_ASN1_OBJECT", header: "openssl/evp.h".}
proc a2d_ASN1_OBJECT*(output: ptr cuchar; olen: cint; buf: cstring; num: cint): cint {.
    importc: "a2d_ASN1_OBJECT", header: "openssl/evp.h".}
proc ASN1_OBJECT_create*(nid: cint; data: ptr cuchar; len: cint; sn: cstring; 
                         ln: cstring): ptr ASN1_OBJECT {.
    importc: "ASN1_OBJECT_create", header: "openssl/evp.h".}
proc ASN1_INTEGER_set*(a: ptr ASN1_INTEGER; v: clong): cint {.
    importc: "ASN1_INTEGER_set", header: "openssl/evp.h".}
proc ASN1_INTEGER_get*(a: ptr ASN1_INTEGER): clong {.
    importc: "ASN1_INTEGER_get", header: "openssl/evp.h".}
proc BN_to_ASN1_INTEGER*(bn: ptr BIGNUM; ai: ptr ASN1_INTEGER): ptr ASN1_INTEGER {.
    importc: "BN_to_ASN1_INTEGER", header: "openssl/evp.h".}
proc ASN1_INTEGER_to_BN*(ai: ptr ASN1_INTEGER; bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "ASN1_INTEGER_to_BN", header: "openssl/evp.h".}
proc ASN1_ENUMERATED_set*(a: ptr ASN1_ENUMERATED; v: clong): cint {.
    importc: "ASN1_ENUMERATED_set", header: "openssl/evp.h".}
proc ASN1_ENUMERATED_get*(a: ptr ASN1_ENUMERATED): clong {.
    importc: "ASN1_ENUMERATED_get", header: "openssl/evp.h".}
proc BN_to_ASN1_ENUMERATED*(bn: ptr BIGNUM; ai: ptr ASN1_ENUMERATED): ptr ASN1_ENUMERATED {.
    importc: "BN_to_ASN1_ENUMERATED", header: "openssl/evp.h".}
proc ASN1_ENUMERATED_to_BN*(ai: ptr ASN1_ENUMERATED; bn: ptr BIGNUM): ptr BIGNUM {.
    importc: "ASN1_ENUMERATED_to_BN", header: "openssl/evp.h".}
proc ASN1_PRINTABLE_type*(s: ptr cuchar; max: cint): cint {.
    importc: "ASN1_PRINTABLE_type", header: "openssl/evp.h".}
proc i2d_ASN1_bytes*(a: ptr ASN1_STRING; pp: ptr ptr cuchar; tag: cint; 
                     xclass: cint): cint {.importc: "i2d_ASN1_bytes", 
    header: "openssl/evp.h".}
proc d2i_ASN1_bytes*(a: ptr ptr ASN1_STRING; pp: ptr ptr cuchar; length: clong; 
                     Ptag: cint; Pclass: cint): ptr ASN1_STRING {.
    importc: "d2i_ASN1_bytes", header: "openssl/evp.h".}
proc ASN1_tag2bit*(tag: cint): culong {.importc: "ASN1_tag2bit", 
                                        header: "openssl/evp.h".}
proc d2i_ASN1_type_bytes*(a: ptr ptr ASN1_STRING; pp: ptr ptr cuchar; 
                          length: clong; typ: cint): ptr ASN1_STRING {.
    importc: "d2i_ASN1_type_bytes", header: "openssl/evp.h".}
proc asn1_Finish*(c: ptr ASN1_CTX): cint {.importc: "asn1_Finish", 
    header: "openssl/evp.h".}
proc asn1_const_Finish*(c: ptr ASN1_const_CTX): cint {.
    importc: "asn1_const_Finish", header: "openssl/evp.h".}
proc ASN1_get_object*(pp: ptr ptr cuchar; plength: ptr clong; ptag: ptr cint; 
                      pclass: ptr cint; omax: clong): cint {.
    importc: "ASN1_get_object", header: "openssl/evp.h".}
proc ASN1_check_infinite_end*(p: ptr ptr cuchar; len: clong): cint {.
    importc: "ASN1_check_infinite_end", header: "openssl/evp.h".}
proc ASN1_const_check_infinite_end*(p: ptr ptr cuchar; len: clong): cint {.
    importc: "ASN1_const_check_infinite_end", header: "openssl/evp.h".}
proc ASN1_put_object*(pp: ptr ptr cuchar; constructed: cint; length: cint; 
                      tag: cint; xclass: cint) {.importc: "ASN1_put_object", 
    header: "openssl/evp.h".}
proc ASN1_put_eoc*(pp: ptr ptr cuchar): cint {.importc: "ASN1_put_eoc", 
    header: "openssl/evp.h".}
proc ASN1_object_size*(constructed: cint; length: cint; tag: cint): cint {.
    importc: "ASN1_object_size", header: "openssl/evp.h".}
proc ASN1_dup*(i2d: ptr i2d_of_void; d2i: ptr d2i_of_void; x: pointer): pointer {.
    importc: "ASN1_dup", header: "openssl/evp.h".}
proc ASN1_item_dup*(it: ptr ASN1_ITEM; x: pointer): pointer {.
    importc: "ASN1_item_dup", header: "openssl/evp.h".}
proc ASN1_d2i_fp*(xnew: proc (): pointer; d2i: ptr d2i_of_void; input: ptr FILE; 
                  x: ptr pointer): pointer {.importc: "ASN1_d2i_fp", 
    header: "openssl/evp.h".}
proc ASN1_item_d2i_fp*(it: ptr ASN1_ITEM; input: ptr FILE; x: pointer): pointer {.
    importc: "ASN1_item_d2i_fp", header: "openssl/evp.h".}
proc ASN1_i2d_fp*(i2d: ptr i2d_of_void; output: ptr FILE; x: pointer): cint {.
    importc: "ASN1_i2d_fp", header: "openssl/evp.h".}
proc ASN1_item_i2d_fp*(it: ptr ASN1_ITEM; output: ptr FILE; x: pointer): cint {.
    importc: "ASN1_item_i2d_fp", header: "openssl/evp.h".}
proc ASN1_STRING_print_ex_fp*(fp: ptr FILE; str: ptr ASN1_STRING; flags: culong): cint {.
    importc: "ASN1_STRING_print_ex_fp", header: "openssl/evp.h".}
proc ASN1_STRING_to_UTF8*(output: ptr ptr cuchar; input: ptr ASN1_STRING): cint {.
    importc: "ASN1_STRING_to_UTF8", header: "openssl/evp.h".}
proc ASN1_d2i_bio*(xnew: proc (): pointer; d2i: ptr d2i_of_void; input: ptr BIO; 
                   x: ptr pointer): pointer {.importc: "ASN1_d2i_bio", 
    header: "openssl/evp.h".}
proc ASN1_item_d2i_bio*(it: ptr ASN1_ITEM; input: ptr BIO; x: pointer): pointer {.
    importc: "ASN1_item_d2i_bio", header: "openssl/evp.h".}
proc ASN1_i2d_bio*(i2d: ptr i2d_of_void; output: ptr BIO; x: ptr cuchar): cint {.
    importc: "ASN1_i2d_bio", header: "openssl/evp.h".}
proc ASN1_item_i2d_bio*(it: ptr ASN1_ITEM; output: ptr BIO; x: pointer): cint {.
    importc: "ASN1_item_i2d_bio", header: "openssl/evp.h".}
proc ASN1_UTCTIME_print*(fp: ptr BIO; a: ptr ASN1_UTCTIME): cint {.
    importc: "ASN1_UTCTIME_print", header: "openssl/evp.h".}
proc ASN1_GENERALIZEDTIME_print*(fp: ptr BIO; a: ptr ASN1_GENERALIZEDTIME): cint {.
    importc: "ASN1_GENERALIZEDTIME_print", header: "openssl/evp.h".}
proc ASN1_TIME_print*(fp: ptr BIO; a: ptr ASN1_TIME): cint {.
    importc: "ASN1_TIME_print", header: "openssl/evp.h".}
proc ASN1_STRING_print*(bp: ptr BIO; v: ptr ASN1_STRING): cint {.
    importc: "ASN1_STRING_print", header: "openssl/evp.h".}
proc ASN1_STRING_print_ex*(output: ptr BIO; str: ptr ASN1_STRING; flags: culong): cint {.
    importc: "ASN1_STRING_print_ex", header: "openssl/evp.h".}
proc ASN1_bn_print*(bp: ptr BIO; number: cstring; num: ptr BIGNUM; 
                    buf: ptr cuchar; off: cint): cint {.
    importc: "ASN1_bn_print", header: "openssl/evp.h".}
proc ASN1_parse*(bp: ptr BIO; pp: ptr cuchar; len: clong; indent: cint): cint {.
    importc: "ASN1_parse", header: "openssl/evp.h".}
proc ASN1_parse_dump*(bp: ptr BIO; pp: ptr cuchar; len: clong; indent: cint; 
                      dump: cint): cint {.importc: "ASN1_parse_dump", 
    header: "openssl/evp.h".}
proc ASN1_tag2str*(tag: cint): cstring {.importc: "ASN1_tag2str", 
    header: "openssl/evp.h".}
proc NETSCAPE_X509_new*(): ptr NETSCAPE_X509 {.importc: "NETSCAPE_X509_new", 
    header: "openssl/evp.h".}
proc NETSCAPE_X509_free*(a: ptr NETSCAPE_X509) {.importc: "NETSCAPE_X509_free", 
    header: "openssl/evp.h".}
proc d2i_NETSCAPE_X509*(a: ptr ptr NETSCAPE_X509; input: ptr ptr cuchar; 
                        len: clong): ptr NETSCAPE_X509 {.
    importc: "d2i_NETSCAPE_X509", header: "openssl/evp.h".}
proc i2d_NETSCAPE_X509*(a: ptr NETSCAPE_X509; output: ptr ptr cuchar): cint {.
    importc: "i2d_NETSCAPE_X509", header: "openssl/evp.h".}
var NETSCAPE_X509_it* {.importc: "NETSCAPE_X509_it", header: "openssl/evp.h".}: ASN1_ITEM

proc ASN1_UNIVERSALSTRING_to_string*(s: ptr ASN1_UNIVERSALSTRING): cint {.
    importc: "ASN1_UNIVERSALSTRING_to_string", header: "openssl/evp.h".}
proc ASN1_TYPE_set_octetstring*(a: ptr ASN1_TYPE; data: ptr cuchar; len: cint): cint {.
    importc: "ASN1_TYPE_set_octetstring", header: "openssl/evp.h".}
proc ASN1_TYPE_get_octetstring*(a: ptr ASN1_TYPE; data: ptr cuchar; 
                                max_len: cint): cint {.
    importc: "ASN1_TYPE_get_octetstring", header: "openssl/evp.h".}
proc ASN1_TYPE_set_int_octetstring*(a: ptr ASN1_TYPE; num: clong; 
                                    data: ptr cuchar; len: cint): cint {.
    importc: "ASN1_TYPE_set_int_octetstring", header: "openssl/evp.h".}
proc ASN1_TYPE_get_int_octetstring*(a: ptr ASN1_TYPE; num: ptr clong; 
                                    data: ptr cuchar; max_len: cint): cint {.
    importc: "ASN1_TYPE_get_int_octetstring", header: "openssl/evp.h".}
proc ASN1_seq_unpack*(buf: ptr cuchar; len: cint; d2i: ptr d2i_of_void; 
                      free_func: proc (a2: OPENSSL_BLOCK)): ptr stack_st_OPENSSL_BLOCK {.
    importc: "ASN1_seq_unpack", header: "openssl/evp.h".}
proc ASN1_seq_pack*(safes: ptr stack_st_OPENSSL_BLOCK; i2d: ptr i2d_of_void; 
                    buf: ptr ptr cuchar; len: ptr cint): ptr cuchar {.
    importc: "ASN1_seq_pack", header: "openssl/evp.h".}
proc ASN1_unpack_string*(oct: ptr ASN1_STRING; d2i: ptr d2i_of_void): pointer {.
    importc: "ASN1_unpack_string", header: "openssl/evp.h".}
proc ASN1_item_unpack*(oct: ptr ASN1_STRING; it: ptr ASN1_ITEM): pointer {.
    importc: "ASN1_item_unpack", header: "openssl/evp.h".}
proc ASN1_pack_string*(obj: pointer; i2d: ptr i2d_of_void; 
                       oct: ptr ptr ASN1_OCTET_STRING): ptr ASN1_STRING {.
    importc: "ASN1_pack_string", header: "openssl/evp.h".}
proc ASN1_item_pack*(obj: pointer; it: ptr ASN1_ITEM; 
                     oct: ptr ptr ASN1_OCTET_STRING): ptr ASN1_STRING {.
    importc: "ASN1_item_pack", header: "openssl/evp.h".}
proc ASN1_STRING_set_default_mask*(mask: culong) {.
    importc: "ASN1_STRING_set_default_mask", header: "openssl/evp.h".}
proc ASN1_STRING_set_default_mask_asc*(p: cstring): cint {.
    importc: "ASN1_STRING_set_default_mask_asc", header: "openssl/evp.h".}
proc ASN1_STRING_get_default_mask*(): culong {.
    importc: "ASN1_STRING_get_default_mask", header: "openssl/evp.h".}
proc ASN1_mbstring_copy*(output: ptr ptr ASN1_STRING; input: ptr cuchar; 
                         len: cint; inform: cint; mask: culong): cint {.
    importc: "ASN1_mbstring_copy", header: "openssl/evp.h".}
proc ASN1_mbstring_ncopy*(output: ptr ptr ASN1_STRING; input: ptr cuchar; 
                          len: cint; inform: cint; mask: culong; minsize: clong; 
                          maxsize: clong): cint {.
    importc: "ASN1_mbstring_ncopy", header: "openssl/evp.h".}
proc ASN1_STRING_set_by_NID*(output: ptr ptr ASN1_STRING; input: ptr cuchar; 
                             inlen: cint; inform: cint; nid: cint): ptr ASN1_STRING {.
    importc: "ASN1_STRING_set_by_NID", header: "openssl/evp.h".}
proc ASN1_STRING_TABLE_get*(nid: cint): ptr ASN1_STRING_TABLE {.
    importc: "ASN1_STRING_TABLE_get", header: "openssl/evp.h".}
proc ASN1_STRING_TABLE_add*(a2: cint; a3: clong; a4: clong; a5: culong; 
                            a6: culong): cint {.
    importc: "ASN1_STRING_TABLE_add", header: "openssl/evp.h".}
proc ASN1_STRING_TABLE_cleanup*() {.importc: "ASN1_STRING_TABLE_cleanup", 
                                    header: "openssl/evp.h".}
proc ASN1_item_new*(it: ptr ASN1_ITEM): ptr ASN1_VALUE {.
    importc: "ASN1_item_new", header: "openssl/evp.h".}
proc ASN1_item_free*(val: ptr ASN1_VALUE; it: ptr ASN1_ITEM) {.
    importc: "ASN1_item_free", header: "openssl/evp.h".}
proc ASN1_item_d2i*(val: ptr ptr ASN1_VALUE; input: ptr ptr cuchar; len: clong; 
                    it: ptr ASN1_ITEM): ptr ASN1_VALUE {.
    importc: "ASN1_item_d2i", header: "openssl/evp.h".}
proc ASN1_item_i2d*(val: ptr ASN1_VALUE; output: ptr ptr cuchar; 
                    it: ptr ASN1_ITEM): cint {.importc: "ASN1_item_i2d", 
    header: "openssl/evp.h".}
proc ASN1_item_ndef_i2d*(val: ptr ASN1_VALUE; output: ptr ptr cuchar; 
                         it: ptr ASN1_ITEM): cint {.
    importc: "ASN1_item_ndef_i2d", header: "openssl/evp.h".}
proc ASN1_add_oid_module*() {.importc: "ASN1_add_oid_module", 
                              header: "openssl/evp.h".}
proc ASN1_generate_nconf*(str: cstring; nconf: ptr CONF): ptr ASN1_TYPE {.
    importc: "ASN1_generate_nconf", header: "openssl/evp.h".}
proc ASN1_generate_v3*(str: cstring; cnf: ptr X509V3_CTX): ptr ASN1_TYPE {.
    importc: "ASN1_generate_v3", header: "openssl/evp.h".}
proc ASN1_item_print*(output: ptr BIO; ifld: ptr ASN1_VALUE; indent: cint; 
                      it: ptr ASN1_ITEM; pctx: ptr ASN1_PCTX): cint {.
    importc: "ASN1_item_print", header: "openssl/evp.h".}
proc ASN1_PCTX_new*(): ptr ASN1_PCTX {.importc: "ASN1_PCTX_new", 
                                       header: "openssl/evp.h".}
proc ASN1_PCTX_free*(p: ptr ASN1_PCTX) {.importc: "ASN1_PCTX_free", 
    header: "openssl/evp.h".}
proc ASN1_PCTX_get_flags*(p: ptr ASN1_PCTX): culong {.
    importc: "ASN1_PCTX_get_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_set_flags*(p: ptr ASN1_PCTX; flags: culong) {.
    importc: "ASN1_PCTX_set_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_get_nm_flags*(p: ptr ASN1_PCTX): culong {.
    importc: "ASN1_PCTX_get_nm_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_set_nm_flags*(p: ptr ASN1_PCTX; flags: culong) {.
    importc: "ASN1_PCTX_set_nm_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_get_cert_flags*(p: ptr ASN1_PCTX): culong {.
    importc: "ASN1_PCTX_get_cert_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_set_cert_flags*(p: ptr ASN1_PCTX; flags: culong) {.
    importc: "ASN1_PCTX_set_cert_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_get_oid_flags*(p: ptr ASN1_PCTX): culong {.
    importc: "ASN1_PCTX_get_oid_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_set_oid_flags*(p: ptr ASN1_PCTX; flags: culong) {.
    importc: "ASN1_PCTX_set_oid_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_get_str_flags*(p: ptr ASN1_PCTX): culong {.
    importc: "ASN1_PCTX_get_str_flags", header: "openssl/evp.h".}
proc ASN1_PCTX_set_str_flags*(p: ptr ASN1_PCTX; flags: culong) {.
    importc: "ASN1_PCTX_set_str_flags", header: "openssl/evp.h".}
proc BIO_f_asn1*(): ptr BIO_METHOD {.importc: "BIO_f_asn1", 
                                     header: "openssl/evp.h".}
proc BIO_new_NDEF*(output: ptr BIO; val: ptr ASN1_VALUE; it: ptr ASN1_ITEM): ptr BIO {.
    importc: "BIO_new_NDEF", header: "openssl/evp.h".}
proc i2d_ASN1_bio_stream*(output: ptr BIO; val: ptr ASN1_VALUE; input: ptr BIO; 
                          flags: cint; it: ptr ASN1_ITEM): cint {.
    importc: "i2d_ASN1_bio_stream", header: "openssl/evp.h".}
proc PEM_write_bio_ASN1_stream*(output: ptr BIO; val: ptr ASN1_VALUE; 
                                input: ptr BIO; flags: cint; hdr: cstring; 
                                it: ptr ASN1_ITEM): cint {.
    importc: "PEM_write_bio_ASN1_stream", header: "openssl/evp.h".}
proc SMIME_write_ASN1*(bio: ptr BIO; val: ptr ASN1_VALUE; data: ptr BIO; 
                       flags: cint; ctype_nid: cint; econt_nid: cint; 
                       mdalgs: ptr stack_st_X509_ALGOR; it: ptr ASN1_ITEM): cint {.
    importc: "SMIME_write_ASN1", header: "openssl/evp.h".}
proc SMIME_read_ASN1*(bio: ptr BIO; bcont: ptr ptr BIO; it: ptr ASN1_ITEM): ptr ASN1_VALUE {.
    importc: "SMIME_read_ASN1", header: "openssl/evp.h".}
proc SMIME_crlf_copy*(input: ptr BIO; output: ptr BIO; flags: cint): cint {.
    importc: "SMIME_crlf_copy", header: "openssl/evp.h".}
proc SMIME_text*(input: ptr BIO; output: ptr BIO): cint {.importc: "SMIME_text", 
    header: "openssl/evp.h".}
proc ERR_load_ASN1_strings*() {.importc: "ERR_load_ASN1_strings", 
                                header: "openssl/evp.h".}
type 
  OBJ_NAME* {.importc: "OBJ_NAME", header: "openssl/evp.h".} = object 
    typ* {.importc: "type".}: cint
    alias* {.importc: "alias".}: cint
    name* {.importc: "name".}: cstring
    data* {.importc: "data".}: cstring


proc OBJ_NAME_init*(): cint {.importc: "OBJ_NAME_init", header: "openssl/evp.h".}
proc OBJ_NAME_new_index*(hash_func: proc (a2: cstring): culong; 
                         cmp_func: proc (a2: cstring; a3: cstring): cint; 
                         free_func: proc (a2: cstring; a3: cint; a4: cstring)): cint {.
    importc: "OBJ_NAME_new_index", header: "openssl/evp.h".}
proc OBJ_NAME_get*(name: cstring; typ: cint): cstring {.importc: "OBJ_NAME_get", 
    header: "openssl/evp.h".}
proc OBJ_NAME_add*(name: cstring; typ: cint; data: cstring): cint {.
    importc: "OBJ_NAME_add", header: "openssl/evp.h".}
proc OBJ_NAME_remove*(name: cstring; typ: cint): cint {.
    importc: "OBJ_NAME_remove", header: "openssl/evp.h".}
proc OBJ_NAME_cleanup*(typ: cint) {.importc: "OBJ_NAME_cleanup", 
                                    header: "openssl/evp.h".}
proc OBJ_NAME_do_all*(typ: cint; fn: proc (a2: ptr OBJ_NAME; arg: pointer); 
                      arg: pointer) {.importc: "OBJ_NAME_do_all", 
                                      header: "openssl/evp.h".}
proc OBJ_NAME_do_all_sorted*(typ: cint; 
                             fn: proc (a2: ptr OBJ_NAME; arg: pointer); 
                             arg: pointer) {.importc: "OBJ_NAME_do_all_sorted", 
    header: "openssl/evp.h".}
proc OBJ_dup*(o: ptr ASN1_OBJECT): ptr ASN1_OBJECT {.importc: "OBJ_dup", 
    header: "openssl/evp.h".}
proc OBJ_nid2obj*(n: cint): ptr ASN1_OBJECT {.importc: "OBJ_nid2obj", 
    header: "openssl/evp.h".}
proc OBJ_nid2ln*(n: cint): cstring {.importc: "OBJ_nid2ln", 
                                     header: "openssl/evp.h".}
proc OBJ_nid2sn*(n: cint): cstring {.importc: "OBJ_nid2sn", 
                                     header: "openssl/evp.h".}
proc OBJ_obj2nid*(o: ptr ASN1_OBJECT): cint {.importc: "OBJ_obj2nid", 
    header: "openssl/evp.h".}
proc OBJ_txt2obj*(s: cstring; no_name: cint): ptr ASN1_OBJECT {.
    importc: "OBJ_txt2obj", header: "openssl/evp.h".}
proc OBJ_obj2txt*(buf: cstring; buf_len: cint; a: ptr ASN1_OBJECT; no_name: cint): cint {.
    importc: "OBJ_obj2txt", header: "openssl/evp.h".}
proc OBJ_txt2nid*(s: cstring): cint {.importc: "OBJ_txt2nid", 
                                      header: "openssl/evp.h".}
proc OBJ_ln2nid*(s: cstring): cint {.importc: "OBJ_ln2nid", 
                                     header: "openssl/evp.h".}
proc OBJ_sn2nid*(s: cstring): cint {.importc: "OBJ_sn2nid", 
                                     header: "openssl/evp.h".}
proc OBJ_cmp*(a: ptr ASN1_OBJECT; b: ptr ASN1_OBJECT): cint {.
    importc: "OBJ_cmp", header: "openssl/evp.h".}
proc OBJ_bsearch_*(key: pointer; base: pointer; num: cint; size: cint; 
                   cmp: proc (a2: pointer; a3: pointer): cint): pointer {.
    importc: "OBJ_bsearch_", header: "openssl/evp.h".}
proc OBJ_bsearch_ex_*(key: pointer; base: pointer; num: cint; size: cint; 
                      cmp: proc (a2: pointer; a3: pointer): cint; flags: cint): pointer {.
    importc: "OBJ_bsearch_ex_", header: "openssl/evp.h".}
proc OBJ_new_nid*(num: cint): cint {.importc: "OBJ_new_nid", 
                                     header: "openssl/evp.h".}
proc OBJ_add_object*(obj: ptr ASN1_OBJECT): cint {.importc: "OBJ_add_object", 
    header: "openssl/evp.h".}
proc OBJ_create*(oid: cstring; sn: cstring; ln: cstring): cint {.
    importc: "OBJ_create", header: "openssl/evp.h".}
proc OBJ_cleanup*() {.importc: "OBJ_cleanup", header: "openssl/evp.h".}
proc OBJ_create_objects*(input: ptr BIO): cint {.importc: "OBJ_create_objects", 
    header: "openssl/evp.h".}
proc OBJ_find_sigid_algs*(signid: cint; pdig_nid: ptr cint; ppkey_nid: ptr cint): cint {.
    importc: "OBJ_find_sigid_algs", header: "openssl/evp.h".}
proc OBJ_find_sigid_by_algs*(psignid: ptr cint; dig_nid: cint; pkey_nid: cint): cint {.
    importc: "OBJ_find_sigid_by_algs", header: "openssl/evp.h".}
proc OBJ_add_sigid*(signid: cint; dig_id: cint; pkey_id: cint): cint {.
    importc: "OBJ_add_sigid", header: "openssl/evp.h".}
proc OBJ_sigid_free*() {.importc: "OBJ_sigid_free", header: "openssl/evp.h".}
var obj_cleanup_defer* {.importc: "obj_cleanup_defer", header: "openssl/evp.h".}: cint

proc check_defer*(nid: cint) {.importc: "check_defer", header: "openssl/evp.h".}
proc ERR_load_OBJ_strings*() {.importc: "ERR_load_OBJ_strings", 
                               header: "openssl/evp.h".}