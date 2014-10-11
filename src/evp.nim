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
#
##define EVP_RC2_KEY_SIZE		16
##define EVP_RC4_KEY_SIZE		16
##define EVP_BLOWFISH_KEY_SIZE		16
##define EVP_CAST5_KEY_SIZE		16
##define EVP_RC5_32_12_16_KEY_SIZE	16
#

const 
  EVP_MAX_MD_SIZE* = 64
  EVP_MAX_KEY_LENGTH* = 64
  EVP_MAX_IV_LENGTH* = 16
  EVP_MAX_BLOCK_LENGTH* = 32
  PKCS5_SALT_LEN* = 8

# Default PKCS#5 iteration count 

const 
  PKCS5_DEFAULT_ITER* = 2048

const 
  EVP_PK_RSA* = 0x00000001
  EVP_PK_DSA* = 0x00000002
  EVP_PK_DH* = 0x00000004
  EVP_PK_EC* = 0x00000008
  EVP_PKT_SIGN* = 0x00000010
  EVP_PKT_ENC* = 0x00000020
  EVP_PKT_EXCH* = 0x00000040
  EVP_PKS_RSA* = 0x00000100
  EVP_PKS_DSA* = 0x00000200
  EVP_PKS_EC* = 0x00000400
  EVP_PKT_EXP* = 0x00001000
  
var
  EVP_PKEY_NONE* {.importc: "EVP_PKEY_NONE", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_RSA* {.importc: "EVP_PKEY_RSA", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_RSA2* {.importc: "EVP_PKEY_RSA2", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_DSA* {.importc: "EVP_PKEY_DSA", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_DSA1* {.importc: "EVP_PKEY_DSA1", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_DSA2* {.importc: "EVP_PKEY_DSA2", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_DSA3* {.importc: "EVP_PKEY_DSA3", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_DSA4* {.importc: "EVP_PKEY_DSA4", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_DH* {.importc: "EVP_PKEY_DH", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_EC* {.importc: "EVP_PKEY_EC", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_HMAC* {.importc: "EVP_PKEY_HMAC", header: "<openssl/evp.h>".} : cint
  EVP_PKEY_CMAC* {.importc: "EVP_PKEY_CMAC", header: "<openssl/evp.h>".} : cint
  
  # couldn't define this one, so importing from header (possible typo in evp.h?)
  EVP_PKEY_OP_TYPE_NOGEN {.importc: "EVP_PKEY_OP_TYPE_NOGEN", header: "<openssl/evp.h>".} : cint
  #EVP_PKEY_OP_SIG* {.importc: "EVP_PKEY_OP_SIG", header: "<openssl/evp.h>".} : cint
  #EVP_PKEY_OP_CRYPT* {.importc: "EVP_PKEY_OP_CRYPT", header: "<openssl/evp.h>".} : cint

type
  # CHECK THESE ARE CORRECT TYPE i.e not some int constant or something
  ec_key_st* {.importc: "ec_key_st", header: "<openssl/evp.h>",final, pure.} = object
  dh_st* {.importc: "dh_st", header: "<openssl/evp.h>",final, pure.} = object
  dsa_st* {.importc: "dsa_st", header: "<openssl/evp.h>",final, pure.} = object
  rsa_st* {.importc: "rsa_st", header: "<openssl/evp.h>",final, pure.} = object 
  EVP_PKEY_ASN1_METHOD* {.importc: "EVP_PKEY_ASN1_METHOD", header: "<openssl/evp.h>",final, pure.} = object
  ENGINE* {.importc: "ENGINE", header: "<openssl/evp.h>",final, pure.} = object
  stack_st_X509_ATTRIBUTE* {.importc: "stack_st_X509_ATTRIBUTE", header: "<openssl/evp.h>",final, pure.} = object
  EVP_MD_CTX* {.importc: "EVP_MD_CTX", header: "<openssl/evp.h>",final, pure.} = object
  EVP_MD* {.importc: "EVP_MD", header: "<openssl/evp.h>",final, pure.} = object
  EVP_PKEY_CTX* {.importc: "EVP_PKEY_CTX", header: "<openssl/evp.h>",final, pure.} = object
  EVP_CIPHER_CTX* {.importc: "EVP_CIPHER_CTX", header: "<openssl/evp.h>",final, pure.} = object
  ASN1_TYPE* {.importc: "ASN1_TYPE", header: "<openssl/evp.h>",final, pure.} = object
  T_EVP_CIPHER* {.importc: "EVP_CIPHER", header: "<openssl/evp.h>",final, pure.} = object
  EVP_PKEY* {.importc: "EVP_PKEY", header: "<openssl/evp.h>",final, pure.} = object
  BIO_METHOD* {.importc: "BIO_METHOD", header: "<openssl/evp.h>",final, pure.} = object
  BIO* {.importc: "BIO", header: "<openssl/evp.h>",final, pure.} = object
  ASN1_PCTX* {.importc: "ASN1_PCTX", header: "<openssl/evp.h>",final, pure.} = object
  ASN1_OBJECT* {.importc: "ASN1_OBJECT", header: "<openssl/evp.h>",final, pure.} = object
  EVP_PBE_KEYGEN* {.importc: "EVP_PBE_KEYGEN", header: "<openssl/evp.h>",final, pure.} = object
  X509_PUBKEY* {.importc: "X509_PUBKEY", header: "<openssl/evp.h>",final, pure.} = object
  PKCS8_PRIV_KEY_INFO* {.importc: "PKCS8_PRIV_KEY_INFO", header: "<openssl/evp.h>",final, pure.} = object
  EVP_PKEY_METHOD* {.importc: "EVP_PKEY_METHOD", header: "<openssl/evp.h>",final, pure.} = object
  
  evp_pkey* = object  {.union.}
    pntr*: cstring
    rsa*: ptr rsa_st
    dsa*: ptr dsa_st
    dh*: ptr dh_st
    ec*: ptr ec_key_st

  evp_pkey_st* = object 
    typ*: cint
    save_type*: cint
    references*: cint
    ameth*: ptr EVP_PKEY_ASN1_METHOD
    engine*: ptr ENGINE
    pkey*: evp_pkey
    save_parameters*: cint
    attributes*: ptr stack_st_X509_ATTRIBUTE

const 
  EVP_PKEY_MO_SIGN* = 0x00000001
  EVP_PKEY_MO_VERIFY* = 0x00000002
  EVP_PKEY_MO_ENCRYPT* = 0x00000004
  EVP_PKEY_MO_DECRYPT* = 0x00000008

type 
  env_md_st* = object 
    typ*: cint
    pkey_type*: cint
    md_size*: cint
    flags*: culong
    init*: proc (ctx: ptr EVP_MD_CTX): cint {.cdecl.}
    update*: proc (ctx: ptr EVP_MD_CTX; data: pointer; count: csize): cint {.
        cdecl.}
    final*: proc (ctx: ptr EVP_MD_CTX; md: ptr cuchar): cint {.cdecl.}
    copy*: proc (to: ptr EVP_MD_CTX; frm: ptr EVP_MD_CTX): cint {.cdecl.}
    cleanup*: proc (ctx: ptr EVP_MD_CTX): cint {.cdecl.}
    sign*: proc (typ: cint; m: ptr cuchar; m_length: cuint; sigret: ptr cuchar; 
                 siglen: ptr cuint; key: pointer): cint {.cdecl.}
    verify*: proc (typ: cint; m: ptr cuchar; m_length: cuint; 
                   sigbuf: ptr cuchar; siglen: cuint; key: pointer): cint {.
        cdecl.}
    required_pkey_type*: array[5, cint]
    block_size*: cint
    ctx_size*: cint
    md_ctrl*: proc (ctx: ptr EVP_MD_CTX; cmd: cint; p1: cint; p2: pointer): cint {.
        cdecl.}

  evp_sign_method* = proc (typ: cint; m: ptr cuchar; m_length: cuint; 
                           sigret: ptr cuchar; siglen: ptr cuint; key: pointer): cint {.
      cdecl.}
  evp_verify_method* = proc (typ: cint; m: ptr cuchar; m_length: cuint; 
                             sigbuf: ptr cuchar; siglen: cuint; key: pointer): cint {.
      cdecl.}

const 
  EVP_MD_FLAG_ONESHOT* = 0x00000001
  EVP_MD_FLAG_PKEY_DIGEST* = 0x00000002

# Digest uses EVP_PKEY_METHOD for signing instead of MD specific signing 

const 
  EVP_MD_FLAG_PKEY_METHOD_SIGNATURE* = 0x00000004

# DigestAlgorithmIdentifier flags... 

const 
  EVP_MD_FLAG_DIGALGID_MASK* = 0x00000018

# NULL or absent parameter accepted. Use NULL 

const 
  EVP_MD_FLAG_DIGALGID_NULL* = 0x00000000

# NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent 

const 
  EVP_MD_FLAG_DIGALGID_ABSENT* = 0x00000008

# Custom handling via ctrl 

const 
  EVP_MD_FLAG_DIGALGID_CUSTOM* = 0x00000018
  EVP_MD_FLAG_FIPS* = 0x00000400

# Digest ctrls 

const 
  EVP_MD_CTRL_DIGALGID* = 0x00000001
  EVP_MD_CTRL_MICALG* = 0x00000002

# Minimum Algorithm specific ctrl value 

const 
  EVP_MD_CTRL_ALG_CTRL* = 0x00001000

type 
  env_md_ctx_st* = object 
    digest*: ptr EVP_MD
    engine*: ptr ENGINE
    flags*: culong
    md_data*: pointer
    pctx*: ptr EVP_PKEY_CTX
    update*: proc (ctx: ptr EVP_MD_CTX; data: pointer; count: csize): cint {.
        cdecl.}


# values for EVP_MD_CTX flags 

const 
  EVP_MD_CTX_FLAG_ONESHOT* = 0x00000001
  EVP_MD_CTX_FLAG_CLEANED* = 0x00000002
  EVP_MD_CTX_FLAG_REUSE* = 0x00000004

# FIPS and pad options are ignored in 1.0.0, definitions are here
#  so we don't accidentally reuse the values for other purposes.
# 

const 
  EVP_MD_CTX_FLAG_NON_FIPS_ALLOW* = 0x00000008

# The following PAD options are also currently ignored in 1.0.0, digest
#  parameters are handled through EVP_DigestSign*() and EVP_DigestVerify*()
#  instead.
# 

const 
  EVP_MD_CTX_FLAG_PAD_MASK* = 0x000000F0
  EVP_MD_CTX_FLAG_PAD_PKCS1* = 0x00000000
  EVP_MD_CTX_FLAG_PAD_X931* = 0x00000010
  EVP_MD_CTX_FLAG_PAD_PSS* = 0x00000020
  EVP_MD_CTX_FLAG_NO_INIT* = 0x00000100

type 
  evp_cipher_st* = object 
    nid*: cint
    block_size*: cint
    key_len*: cint
    iv_len*: cint
    flags*: culong
    init*: proc (ctx: ptr EVP_CIPHER_CTX; key: ptr cuchar; iv: ptr cuchar; 
                 enc: cint): cint {.cdecl.}
    do_cipher*: proc (ctx: ptr EVP_CIPHER_CTX; output: ptr cuchar; 
                      input: ptr cuchar; inl: csize): cint {.cdecl.}
    cleanup*: proc (a2: ptr EVP_CIPHER_CTX): cint {.cdecl.}
    ctx_size*: cint
    set_asn1_parameters*: proc (a2: ptr EVP_CIPHER_CTX; a3: ptr ASN1_TYPE): cint {.
        cdecl.}
    get_asn1_parameters*: proc (a2: ptr EVP_CIPHER_CTX; a3: ptr ASN1_TYPE): cint {.
        cdecl.}
    ctrl*: proc (a2: ptr EVP_CIPHER_CTX; typ: cint; arg: cint; pntr: pointer): cint {.
        cdecl.}
    app_data*: pointer


# Values for cipher flags 
# Modes for ciphers 

const 
  EVP_CIPH_STREAM_CIPHER* = 0x00000000
  EVP_CIPH_ECB_MODE* = 0x00000001
  EVP_CIPH_CBC_MODE* = 0x00000002
  EVP_CIPH_CFB_MODE* = 0x00000003
  EVP_CIPH_OFB_MODE* = 0x00000004
  EVP_CIPH_CTR_MODE* = 0x00000005
  EVP_CIPH_GCM_MODE* = 0x00000006
  EVP_CIPH_CCM_MODE* = 0x00000007
  EVP_CIPH_XTS_MODE* = 0x00010001
  EVP_CIPH_MODE* = 0x000F0007

# Set if variable length cipher 

const 
  EVP_CIPH_VARIABLE_LENGTH* = 0x00000008

# Set if the iv handling should be done by the cipher itself 

const 
  EVP_CIPH_CUSTOM_IV* = 0x00000010

# Set if the cipher's init() function should be called if key is NULL 

const 
  EVP_CIPH_ALWAYS_CALL_INIT* = 0x00000020

# Call ctrl() to init cipher parameters 

const 
  EVP_CIPH_CTRL_INIT* = 0x00000040

# Don't use standard key length function 

const 
  EVP_CIPH_CUSTOM_KEY_LENGTH* = 0x00000080

# Don't use standard block padding 

const 
  EVP_CIPH_NO_PADDING* = 0x00000100

# cipher handles random key generation 

const 
  EVP_CIPH_RAND_KEY* = 0x00000200

# cipher has its own additional copying logic 

const 
  EVP_CIPH_CUSTOM_COPY* = 0x00000400

# Allow use default ASN1 get/set iv 

const 
  EVP_CIPH_FLAG_DEFAULT_ASN1* = 0x00001000

# Buffer length in bits not bytes: CFB1 mode only 

const 
  EVP_CIPH_FLAG_LENGTH_BITS* = 0x00002000

# Note if suitable for use in FIPS mode 

const 
  EVP_CIPH_FLAG_FIPS* = 0x00004000

# Allow non FIPS cipher in FIPS mode 

const 
  EVP_CIPH_FLAG_NON_FIPS_ALLOW* = 0x00008000

# Cipher handles any and all padding logic as well
#  as finalisation.
# 

const 
  EVP_CIPH_FLAG_CUSTOM_CIPHER* = 0x00100000
  EVP_CIPH_FLAG_AEAD_CIPHER* = 0x00200000

# ctrl() values 

const 
  EVP_CTRL_INIT* = 0x00000000
  EVP_CTRL_SET_KEY_LENGTH* = 0x00000001
  EVP_CTRL_GET_RC2_KEY_BITS* = 0x00000002
  EVP_CTRL_SET_RC2_KEY_BITS* = 0x00000003
  EVP_CTRL_GET_RC5_ROUNDS* = 0x00000004
  EVP_CTRL_SET_RC5_ROUNDS* = 0x00000005
  EVP_CTRL_RAND_KEY* = 0x00000006
  EVP_CTRL_PBE_PRF_NID* = 0x00000007
  EVP_CTRL_COPY* = 0x00000008
  EVP_CTRL_GCM_SET_IVLEN* = 0x00000009
  EVP_CTRL_GCM_GET_TAG* = 0x00000010
  EVP_CTRL_GCM_SET_TAG* = 0x00000011
  EVP_CTRL_GCM_SET_IV_FIXED* = 0x00000012
  EVP_CTRL_GCM_IV_GEN* = 0x00000013
  EVP_CTRL_CCM_SET_IVLEN* = EVP_CTRL_GCM_SET_IVLEN
  EVP_CTRL_CCM_GET_TAG* = EVP_CTRL_GCM_GET_TAG
  EVP_CTRL_CCM_SET_TAG* = EVP_CTRL_GCM_SET_TAG
  EVP_CTRL_CCM_SET_L* = 0x00000014
  EVP_CTRL_CCM_SET_MSGLEN* = 0x00000015

# AEAD cipher deduces payload length and returns number of bytes
#  required to store MAC and eventual padding. Subsequent call to
#  EVP_Cipher even appends/verifies MAC.
# 

const 
  EVP_CTRL_AEAD_TLS1_AAD* = 0x00000016

# Used by composite AEAD ciphers, no-op in GCM, CCM... 

const 
  EVP_CTRL_AEAD_SET_MAC_KEY* = 0x00000017

# Set the GCM invocation field, decrypt only 

const 
  EVP_CTRL_GCM_SET_IV_INV* = 0x00000018

# GCM TLS constants 
# Length of fixed part of IV derived from PRF 

const 
  EVP_GCM_TLS_FIXED_IV_LEN* = 4

# Length of explicit part of IV part of TLS records 

const 
  EVP_GCM_TLS_EXPLICIT_IV_LEN* = 8

# Length of tag for TLS 

const 
  EVP_GCM_TLS_TAG_LEN* = 16

type 
  EVP_CIPHER_INFO* = object 
    cipher*: ptr T_EVP_CIPHER
    iv*: array[16, cuchar]

  evp_cipher_ctx_st* = object 
    cipher*: ptr T_EVP_CIPHER
    engine*: ptr ENGINE
    encrypt*: cint
    buf_len*: cint
    oiv*: array[16, cuchar]
    iv*: array[16, cuchar]
    buf*: array[32, cuchar]
    num*: cint
    app_data*: pointer
    key_len*: cint
    flags*: culong
    cipher_data*: pointer
    final_used*: cint
    block_mask*: cint
    final*: array[32, cuchar]

  EVP_ENCODE_CTX* = object 
    num*: cint
    length*: cint
    enc_data*: array[80, cuchar]
    line_num*: cint
    expect_nl*: cint


#typedef int (EVP_PBE_KEYGEN)(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
#  ASN1_TYPE *param, const EVP_CIPHER *cipher,
#                const EVP_MD *md, int en_de);
# Add some extra combinations 

template EVP_get_digestbynid*(a: expr): expr = 
  EVP_get_digestbyname(OBJ_nid2sn(a))

template EVP_get_digestbyobj*(a: expr): expr = 
  EVP_get_digestbynid(OBJ_obj2nid(a))

template EVP_get_cipherbynid*(a: expr): expr = 
  EVP_get_cipherbyname(OBJ_nid2sn(a))

template EVP_get_cipherbyobj*(a: expr): expr = 
  EVP_get_cipherbynid(OBJ_obj2nid(a))

proc EVP_MD_type*(md: ptr EVP_MD): cint {.cdecl, importc: "EVP_MD_type", 
    dynlib: cryptodll.}
template EVP_MD_nid*(e: expr): expr = 
  EVP_MD_type(e)

template EVP_MD_name*(e: expr): expr = 
  OBJ_nid2sn(EVP_MD_nid(e))

proc EVP_MD_pkey_type*(md: ptr EVP_MD): cint {.cdecl, 
    importc: "EVP_MD_pkey_type", dynlib: cryptodll.}
proc EVP_MD_size*(md: ptr EVP_MD): cint {.cdecl, importc: "EVP_MD_size", 
    dynlib: cryptodll.}
proc EVP_MD_block_size*(md: ptr EVP_MD): cint {.cdecl, 
    importc: "EVP_MD_block_size", dynlib: cryptodll.}
proc EVP_MD_flags*(md: ptr EVP_MD): culong {.cdecl, importc: "EVP_MD_flags", 
    dynlib: cryptodll.}
proc EVP_MD_CTX_md*(ctx: ptr EVP_MD_CTX): ptr EVP_MD {.cdecl, 
    importc: "EVP_MD_CTX_md", dynlib: cryptodll.}
template EVP_MD_CTX_size*(e: expr): expr = 
  EVP_MD_size(EVP_MD_CTX_md(e))

template EVP_MD_CTX_block_size*(e: expr): expr = 
  EVP_MD_block_size(EVP_MD_CTX_md(e))

template EVP_MD_CTX_type*(e: expr): expr = 
  EVP_MD_type(EVP_MD_CTX_md(e))

proc EVP_CIPHER_nid*(cipher: ptr T_EVP_CIPHER): cint {.cdecl, 
    importc: "EVP_CIPHER_nid", dynlib: cryptodll.}
template EVP_CIPHER_name*(e: expr): expr = 
  OBJ_nid2sn(EVP_CIPHER_nid(e))

proc EVP_CIPHER_block_size*(cipher: ptr T_EVP_CIPHER): cint {.cdecl, 
    importc: "EVP_CIPHER_block_size", dynlib: cryptodll.}
proc EVP_CIPHER_key_length*(cipher: ptr T_EVP_CIPHER): cint {.cdecl, 
    importc: "EVP_CIPHER_key_length", dynlib: cryptodll.}
proc EVP_CIPHER_iv_length*(cipher: ptr T_EVP_CIPHER): cint {.cdecl, 
    importc: "EVP_CIPHER_iv_length", dynlib: cryptodll.}
proc EVP_CIPHER_flags*(cipher: ptr T_EVP_CIPHER): culong {.cdecl, 
    importc: "EVP_CIPHER_flags", dynlib: cryptodll.}
template EVP_CIPHER_mode*(e: expr): expr = 
  (EVP_CIPHER_flags(e) and EVP_CIPH_MODE)

proc EVP_CIPHER_CTX_cipher*(ctx: ptr EVP_CIPHER_CTX): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_CIPHER_CTX_cipher", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_nid*(ctx: ptr EVP_CIPHER_CTX): cint {.cdecl, 
    importc: "EVP_CIPHER_CTX_nid", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_block_size*(ctx: ptr EVP_CIPHER_CTX): cint {.cdecl, 
    importc: "EVP_CIPHER_CTX_block_size", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_key_length*(ctx: ptr EVP_CIPHER_CTX): cint {.cdecl, 
    importc: "EVP_CIPHER_CTX_key_length", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_iv_length*(ctx: ptr EVP_CIPHER_CTX): cint {.cdecl, 
    importc: "EVP_CIPHER_CTX_iv_length", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_copy*(output: ptr EVP_CIPHER_CTX; input: ptr EVP_CIPHER_CTX): cint {.
    cdecl, importc: "EVP_CIPHER_CTX_copy", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_get_app_data*(ctx: ptr EVP_CIPHER_CTX): pointer {.cdecl, 
    importc: "EVP_CIPHER_CTX_get_app_data", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_set_app_data*(ctx: ptr EVP_CIPHER_CTX; data: pointer) {.
    cdecl, importc: "EVP_CIPHER_CTX_set_app_data", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_flags*(ctx: ptr EVP_CIPHER_CTX): culong {.cdecl, 
    importc: "EVP_CIPHER_CTX_flags", dynlib: cryptodll.}
template EVP_CIPHER_CTX_type*(c: expr): expr = 
  EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))

template EVP_CIPHER_CTX_mode*(e: expr): expr = 
  (EVP_CIPHER_CTX_flags(e) and EVP_CIPH_MODE)

template EVP_ENCODE_LENGTH*(l: expr): expr = 
  (((l + 2) div 3 * 4) + (l div 48 + 1) * 2 + 80)

template EVP_DECODE_LENGTH*(l: expr): expr = 
  ((l + 3) div 4 * 3 + 80)

template EVP_SignInit_ex*(a, b, c: expr): expr = 
  EVP_DigestInit_ex(a, b, c)

template EVP_SignInit*(a, b: expr): expr = 
  EVP_DigestInit(a, b)

template EVP_SignUpdate*(a, b, c: expr): expr = 
  EVP_DigestUpdate(a, b, c)

template EVP_VerifyInit_ex*(a, b, c: expr): expr = 
  EVP_DigestInit_ex(a, b, c)

template EVP_VerifyInit*(a, b: expr): expr = 
  EVP_DigestInit(a, b)

template EVP_VerifyUpdate*(a, b, c: expr): expr = 
  EVP_DigestUpdate(a, b, c)

template EVP_OpenUpdate*(a, b, c, d, e: expr): expr = 
  EVP_DecryptUpdate(a, b, c, d, e)

template EVP_SealUpdate*(a, b, c, d, e: expr): expr = 
  EVP_EncryptUpdate(a, b, c, d, e)

template EVP_DigestSignUpdate*(a, b, c: expr): expr = 
  EVP_DigestUpdate(a, b, c)

template EVP_DigestVerifyUpdate*(a, b, c: expr): expr = 
  EVP_DigestUpdate(a, b, c)

when defined(CONST_STRICT): 
  proc BIO_set_md*(a2: ptr BIO; md: ptr EVP_MD) {.cdecl, importc: "BIO_set_md", 
      dynlib: cryptodll.}
else: 
  template BIO_set_md*(b, md: expr): expr = 
    BIO_ctrl(b, BIO_C_SET_MD, 0, cast[cstring](md))

template BIO_get_md*(b, mdp: expr): expr = 
  BIO_ctrl(b, BIO_C_GET_MD, 0, cast[cstring](mdp))

template BIO_get_md_ctx*(b, mdcp: expr): expr = 
  BIO_ctrl(b, BIO_C_GET_MD_CTX, 0, cast[cstring](mdcp))

template BIO_set_md_ctx*(b, mdcp: expr): expr = 
  BIO_ctrl(b, BIO_C_SET_MD_CTX, 0, cast[cstring](mdcp))

template BIO_get_cipher_status*(b: expr): expr = 
  BIO_ctrl(b, BIO_C_GET_CIPHER_STATUS, 0, nil)

template BIO_get_cipher_ctx*(b, c_pp: expr): expr = 
  BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, cast[cstring](c_pp))

proc EVP_Cipher*(c: ptr EVP_CIPHER_CTX; output: ptr cuchar; input: ptr cuchar; 
                 inl: cuint): cint {.cdecl, importc: "EVP_Cipher", 
                                     dynlib: cryptodll.}
##define EVP_add_cipher_alias(n,alias) \
#	OBJ_NAME_add((alias),OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n))
##define EVP_add_digest_alias(n,alias) \
#	OBJ_NAME_add((alias),OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n))
##define EVP_delete_cipher_alias(alias) \
#	OBJ_NAME_remove(alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
##define EVP_delete_digest_alias(alias) \
#	OBJ_NAME_remove(alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

proc EVP_MD_CTX_init*(ctx: ptr EVP_MD_CTX) {.cdecl, importc: "EVP_MD_CTX_init", 
    dynlib: cryptodll.}
proc EVP_MD_CTX_cleanup*(ctx: ptr EVP_MD_CTX): cint {.cdecl, 
    importc: "EVP_MD_CTX_cleanup", dynlib: cryptodll.}
proc EVP_MD_CTX_create*(): ptr EVP_MD_CTX {.cdecl, importc: "EVP_MD_CTX_create", 
    dynlib: cryptodll.}
proc EVP_MD_CTX_destroy*(ctx: ptr EVP_MD_CTX) {.cdecl, 
    importc: "EVP_MD_CTX_destroy", dynlib: cryptodll.}
proc EVP_MD_CTX_copy_ex*(output: ptr EVP_MD_CTX; input: ptr EVP_MD_CTX): cint {.
    cdecl, importc: "EVP_MD_CTX_copy_ex", dynlib: cryptodll.}
proc EVP_MD_CTX_set_flags*(ctx: ptr EVP_MD_CTX; flags: cint) {.cdecl, 
    importc: "EVP_MD_CTX_set_flags", dynlib: cryptodll.}
proc EVP_MD_CTX_clear_flags*(ctx: ptr EVP_MD_CTX; flags: cint) {.cdecl, 
    importc: "EVP_MD_CTX_clear_flags", dynlib: cryptodll.}
proc EVP_MD_CTX_test_flags*(ctx: ptr EVP_MD_CTX; flags: cint): cint {.cdecl, 
    importc: "EVP_MD_CTX_test_flags", dynlib: cryptodll.}
proc EVP_DigestInit_ex*(ctx: ptr EVP_MD_CTX; typ: ptr EVP_MD; impl: ptr ENGINE): cint {.
    cdecl, importc: "EVP_DigestInit_ex", dynlib: cryptodll.}
proc EVP_DigestUpdate*(ctx: ptr EVP_MD_CTX; d: pointer; cnt: csize): cint {.
    cdecl, importc: "EVP_DigestUpdate", dynlib: cryptodll.}
proc EVP_DigestFinal_ex*(ctx: ptr EVP_MD_CTX; md: ptr cuchar; s: ptr cuint): cint {.
    cdecl, importc: "EVP_DigestFinal_ex", dynlib: cryptodll.}
proc EVP_Digest*(data: pointer; count: csize; md: ptr cuchar; size: ptr cuint; 
                 typ: ptr EVP_MD; impl: ptr ENGINE): cint {.cdecl, 
    importc: "EVP_Digest", dynlib: cryptodll.}
proc EVP_MD_CTX_copy*(output: ptr EVP_MD_CTX; input: ptr EVP_MD_CTX): cint {.
    cdecl, importc: "EVP_MD_CTX_copy", dynlib: cryptodll.}
proc EVP_DigestInit*(ctx: ptr EVP_MD_CTX; typ: ptr EVP_MD): cint {.cdecl, 
    importc: "EVP_DigestInit", dynlib: cryptodll.}
proc EVP_DigestFinal*(ctx: ptr EVP_MD_CTX; md: ptr cuchar; s: ptr cuint): cint {.
    cdecl, importc: "EVP_DigestFinal", dynlib: cryptodll.}
proc EVP_read_pw_string*(buf: cstring; length: cint; prompt: cstring; 
                         verify: cint): cint {.cdecl, 
    importc: "EVP_read_pw_string", dynlib: cryptodll.}
proc EVP_read_pw_string_min*(buf: cstring; minlen: cint; maxlen: cint; 
                             prompt: cstring; verify: cint): cint {.cdecl, 
    importc: "EVP_read_pw_string_min", dynlib: cryptodll.}
proc EVP_set_pw_prompt*(prompt: cstring) {.cdecl, importc: "EVP_set_pw_prompt", 
    dynlib: cryptodll.}
proc EVP_get_pw_prompt*(): cstring {.cdecl, importc: "EVP_get_pw_prompt", 
                                     dynlib: cryptodll.}
proc EVP_BytesToKey*(typ: ptr T_EVP_CIPHER; md: ptr EVP_MD; salt: ptr cuchar; 
                     data: ptr cuchar; datal: cint; count: cint; 
                     key: ptr cuchar; iv: ptr cuchar): cint {.cdecl, 
    importc: "EVP_BytesToKey", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_set_flags*(ctx: ptr EVP_CIPHER_CTX; flags: cint) {.cdecl, 
    importc: "EVP_CIPHER_CTX_set_flags", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_clear_flags*(ctx: ptr EVP_CIPHER_CTX; flags: cint) {.cdecl, 
    importc: "EVP_CIPHER_CTX_clear_flags", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_test_flags*(ctx: ptr EVP_CIPHER_CTX; flags: cint): cint {.
    cdecl, importc: "EVP_CIPHER_CTX_test_flags", dynlib: cryptodll.}
proc EVP_EncryptInit*(ctx: ptr EVP_CIPHER_CTX; cipher: ptr T_EVP_CIPHER; 
                      key: ptr cuchar; iv: ptr cuchar): cint {.cdecl, 
    importc: "EVP_EncryptInit", dynlib: cryptodll.}
proc EVP_EncryptInit_ex*(ctx: ptr EVP_CIPHER_CTX; cipher: ptr T_EVP_CIPHER; 
                         impl: ptr ENGINE; key: ptr cuchar; iv: ptr cuchar): cint {.
    cdecl, importc: "EVP_EncryptInit_ex", dynlib: cryptodll.}
proc EVP_EncryptUpdate*(ctx: ptr EVP_CIPHER_CTX; output: ptr cuchar; 
                        outl: ptr cint; input: ptr cuchar; inl: cint): cint {.
    cdecl, importc: "EVP_EncryptUpdate", dynlib: cryptodll.}
proc EVP_EncryptFinal_ex*(ctx: ptr EVP_CIPHER_CTX; output: ptr cuchar; 
                          outl: ptr cint): cint {.cdecl, 
    importc: "EVP_EncryptFinal_ex", dynlib: cryptodll.}
proc EVP_EncryptFinal*(ctx: ptr EVP_CIPHER_CTX; output: ptr cuchar; 
                       outl: ptr cint): cint {.cdecl, 
    importc: "EVP_EncryptFinal", dynlib: cryptodll.}
proc EVP_DecryptInit*(ctx: ptr EVP_CIPHER_CTX; cipher: ptr T_EVP_CIPHER; 
                      key: ptr cuchar; iv: ptr cuchar): cint {.cdecl, 
    importc: "EVP_DecryptInit", dynlib: cryptodll.}
proc EVP_DecryptInit_ex*(ctx: ptr EVP_CIPHER_CTX; cipher: ptr T_EVP_CIPHER; 
                         impl: ptr ENGINE; key: ptr cuchar; iv: ptr cuchar): cint {.
    cdecl, importc: "EVP_DecryptInit_ex", dynlib: cryptodll.}
proc EVP_DecryptUpdate*(ctx: ptr EVP_CIPHER_CTX; output: ptr cuchar; 
                        outl: ptr cint; input: ptr cuchar; inl: cint): cint {.
    cdecl, importc: "EVP_DecryptUpdate", dynlib: cryptodll.}
proc EVP_DecryptFinal*(ctx: ptr EVP_CIPHER_CTX; outm: ptr cuchar; outl: ptr cint): cint {.
    cdecl, importc: "EVP_DecryptFinal", dynlib: cryptodll.}
proc EVP_DecryptFinal_ex*(ctx: ptr EVP_CIPHER_CTX; outm: ptr cuchar; 
                          outl: ptr cint): cint {.cdecl, 
    importc: "EVP_DecryptFinal_ex", dynlib: cryptodll.}
proc EVP_CipherInit*(ctx: ptr EVP_CIPHER_CTX; cipher: ptr T_EVP_CIPHER; 
                     key: ptr cuchar; iv: ptr cuchar; enc: cint): cint {.cdecl, 
    importc: "EVP_CipherInit", dynlib: cryptodll.}
proc EVP_CipherInit_ex*(ctx: ptr EVP_CIPHER_CTX; cipher: ptr T_EVP_CIPHER; 
                        impl: ptr ENGINE; key: ptr cuchar; iv: ptr cuchar; 
                        enc: cint): cint {.cdecl, importc: "EVP_CipherInit_ex", 
    dynlib: cryptodll.}
proc EVP_CipherUpdate*(ctx: ptr EVP_CIPHER_CTX; output: ptr cuchar; 
                       outl: ptr cint; input: ptr cuchar; inl: cint): cint {.
    cdecl, importc: "EVP_CipherUpdate", dynlib: cryptodll.}
proc EVP_CipherFinal*(ctx: ptr EVP_CIPHER_CTX; outm: ptr cuchar; outl: ptr cint): cint {.
    cdecl, importc: "EVP_CipherFinal", dynlib: cryptodll.}
proc EVP_CipherFinal_ex*(ctx: ptr EVP_CIPHER_CTX; outm: ptr cuchar; 
                         outl: ptr cint): cint {.cdecl, 
    importc: "EVP_CipherFinal_ex", dynlib: cryptodll.}
proc EVP_SignFinal*(ctx: ptr EVP_MD_CTX; md: ptr cuchar; s: ptr cuint; 
                    pkey: ptr EVP_PKEY): cint {.cdecl, importc: "EVP_SignFinal", 
    dynlib: cryptodll.}
proc EVP_VerifyFinal*(ctx: ptr EVP_MD_CTX; sigbuf: ptr cuchar; siglen: cuint; 
                      pkey: ptr EVP_PKEY): cint {.cdecl, 
    importc: "EVP_VerifyFinal", dynlib: cryptodll.}
proc EVP_DigestSignInit*(ctx: ptr EVP_MD_CTX; pctx: ptr ptr EVP_PKEY_CTX; 
                         typ: ptr EVP_MD; e: ptr ENGINE; pkey: ptr EVP_PKEY): cint {.
    cdecl, importc: "EVP_DigestSignInit", dynlib: cryptodll.}
proc EVP_DigestSignFinal*(ctx: ptr EVP_MD_CTX; sigret: ptr cuchar; 
                          siglen: ptr csize): cint {.cdecl, 
    importc: "EVP_DigestSignFinal", dynlib: cryptodll.}
proc EVP_DigestVerifyInit*(ctx: ptr EVP_MD_CTX; pctx: ptr ptr EVP_PKEY_CTX; 
                           typ: ptr EVP_MD; e: ptr ENGINE; pkey: ptr EVP_PKEY): cint {.
    cdecl, importc: "EVP_DigestVerifyInit", dynlib: cryptodll.}
proc EVP_DigestVerifyFinal*(ctx: ptr EVP_MD_CTX; sig: ptr cuchar; siglen: csize): cint {.
    cdecl, importc: "EVP_DigestVerifyFinal", dynlib: cryptodll.}
proc EVP_OpenInit*(ctx: ptr EVP_CIPHER_CTX; typ: ptr T_EVP_CIPHER; ek: ptr cuchar; 
                   ekl: cint; iv: ptr cuchar; priv: ptr EVP_PKEY): cint {.cdecl, 
    importc: "EVP_OpenInit", dynlib: cryptodll.}
proc EVP_OpenFinal*(ctx: ptr EVP_CIPHER_CTX; output: ptr cuchar; outl: ptr cint): cint {.
    cdecl, importc: "EVP_OpenFinal", dynlib: cryptodll.}
proc EVP_SealInit*(ctx: ptr EVP_CIPHER_CTX; typ: ptr T_EVP_CIPHER; 
                   ek: ptr ptr cuchar; ekl: ptr cint; iv: ptr cuchar; 
                   pubk: ptr ptr EVP_PKEY; npubk: cint): cint {.cdecl, 
    importc: "EVP_SealInit", dynlib: cryptodll.}
proc EVP_SealFinal*(ctx: ptr EVP_CIPHER_CTX; output: ptr cuchar; outl: ptr cint): cint {.
    cdecl, importc: "EVP_SealFinal", dynlib: cryptodll.}
proc EVP_EncodeInit*(ctx: ptr EVP_ENCODE_CTX) {.cdecl, 
    importc: "EVP_EncodeInit", dynlib: cryptodll.}
proc EVP_EncodeUpdate*(ctx: ptr EVP_ENCODE_CTX; output: ptr cuchar; 
                       outl: ptr cint; input: ptr cuchar; inl: cint) {.cdecl, 
    importc: "EVP_EncodeUpdate", dynlib: cryptodll.}
proc EVP_EncodeFinal*(ctx: ptr EVP_ENCODE_CTX; output: ptr cuchar; 
                      outl: ptr cint) {.cdecl, importc: "EVP_EncodeFinal", 
                                        dynlib: cryptodll.}
proc EVP_EncodeBlock*(t: ptr cuchar; f: ptr cuchar; n: cint): cint {.cdecl, 
    importc: "EVP_EncodeBlock", dynlib: cryptodll.}
proc EVP_DecodeInit*(ctx: ptr EVP_ENCODE_CTX) {.cdecl, 
    importc: "EVP_DecodeInit", dynlib: cryptodll.}
proc EVP_DecodeUpdate*(ctx: ptr EVP_ENCODE_CTX; output: ptr cuchar; 
                       outl: ptr cint; input: ptr cuchar; inl: cint): cint {.
    cdecl, importc: "EVP_DecodeUpdate", dynlib: cryptodll.}
proc EVP_DecodeFinal*(ctx: ptr EVP_ENCODE_CTX; output: ptr cuchar; 
                      outl: ptr cint): cint {.cdecl, importc: "EVP_DecodeFinal", 
    dynlib: cryptodll.}
proc EVP_DecodeBlock*(t: ptr cuchar; f: ptr cuchar; n: cint): cint {.cdecl, 
    importc: "EVP_DecodeBlock", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_init*(a: ptr EVP_CIPHER_CTX) {.cdecl, 
    importc: "EVP_CIPHER_CTX_init", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_cleanup*(a: ptr EVP_CIPHER_CTX): cint {.cdecl, 
    importc: "EVP_CIPHER_CTX_cleanup", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_new*(): ptr EVP_CIPHER_CTX {.cdecl, 
    importc: "EVP_CIPHER_CTX_new", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_free*(a: ptr EVP_CIPHER_CTX) {.cdecl, 
    importc: "EVP_CIPHER_CTX_free", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_set_key_length*(x: ptr EVP_CIPHER_CTX; keylen: cint): cint {.
    cdecl, importc: "EVP_CIPHER_CTX_set_key_length", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_set_padding*(c: ptr EVP_CIPHER_CTX; pad: cint): cint {.
    cdecl, importc: "EVP_CIPHER_CTX_set_padding", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_ctrl*(ctx: ptr EVP_CIPHER_CTX; typ: cint; arg: cint; 
                          pntr: pointer): cint {.cdecl, 
    importc: "EVP_CIPHER_CTX_ctrl", dynlib: cryptodll.}
proc EVP_CIPHER_CTX_rand_key*(ctx: ptr EVP_CIPHER_CTX; key: ptr cuchar): cint {.
    cdecl, importc: "EVP_CIPHER_CTX_rand_key", dynlib: cryptodll.}
proc BIO_f_md*(): ptr BIO_METHOD {.cdecl, importc: "BIO_f_md", dynlib: cryptodll.}
proc BIO_f_base64*(): ptr BIO_METHOD {.cdecl, importc: "BIO_f_base64", 
                                       dynlib: cryptodll.}
proc BIO_f_cipher*(): ptr BIO_METHOD {.cdecl, importc: "BIO_f_cipher", 
                                       dynlib: cryptodll.}
proc BIO_f_reliable*(): ptr BIO_METHOD {.cdecl, importc: "BIO_f_reliable", 
    dynlib: cryptodll.}
proc BIO_set_cipher*(b: ptr BIO; c: ptr T_EVP_CIPHER; k: ptr cuchar; 
                     i: ptr cuchar; enc: cint) {.cdecl, 
    importc: "BIO_set_cipher", dynlib: cryptodll.}
proc EVP_md_null*(): ptr EVP_MD {.cdecl, importc: "EVP_md_null", 
                                  dynlib: cryptodll.}
proc EVP_md2*(): ptr EVP_MD {.cdecl, importc: "EVP_md2", dynlib: cryptodll.}
proc EVP_md4*(): ptr EVP_MD {.cdecl, importc: "EVP_md4", dynlib: cryptodll.}
proc EVP_md5*(): ptr EVP_MD {.cdecl, importc: "EVP_md5", dynlib: cryptodll.}
proc EVP_sha*(): ptr EVP_MD {.cdecl, importc: "EVP_sha", dynlib: cryptodll.}
proc EVP_sha1*(): ptr EVP_MD {.cdecl, importc: "EVP_sha1", dynlib: cryptodll.}
proc EVP_dss*(): ptr EVP_MD {.cdecl, importc: "EVP_dss", dynlib: cryptodll.}
proc EVP_dss1*(): ptr EVP_MD {.cdecl, importc: "EVP_dss1", dynlib: cryptodll.}
proc EVP_ecdsa*(): ptr EVP_MD {.cdecl, importc: "EVP_ecdsa", dynlib: cryptodll.}
proc EVP_sha224*(): ptr EVP_MD {.cdecl, importc: "EVP_sha224", dynlib: cryptodll.}
proc EVP_sha256*(): ptr EVP_MD {.cdecl, importc: "EVP_sha256", dynlib: cryptodll.}
proc EVP_sha384*(): ptr EVP_MD {.cdecl, importc: "EVP_sha384", dynlib: cryptodll.}
proc EVP_sha512*(): ptr EVP_MD {.cdecl, importc: "EVP_sha512", dynlib: cryptodll.}
proc EVP_mdc2*(): ptr EVP_MD {.cdecl, importc: "EVP_mdc2", dynlib: cryptodll.}
proc EVP_ripemd160*(): ptr EVP_MD {.cdecl, importc: "EVP_ripemd160", 
                                    dynlib: cryptodll.}
proc EVP_whirlpool*(): ptr EVP_MD {.cdecl, importc: "EVP_whirlpool", 
                                    dynlib: cryptodll.}
proc EVP_enc_null*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_enc_null", 
                                       dynlib: cryptodll.}
proc EVP_des_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ecb", 
                                      dynlib: cryptodll.}
proc EVP_des_ede*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede", 
                                      dynlib: cryptodll.}
proc EVP_des_ede3*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede3", 
                                       dynlib: cryptodll.}
proc EVP_des_ede_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede_ecb", 
    dynlib: cryptodll.}
proc EVP_des_ede3_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede3_ecb", 
    dynlib: cryptodll.}
proc EVP_des_cfb64*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_cfb64", 
                                        dynlib: cryptodll.}
proc EVP_des_cfb1*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_cfb1", 
                                       dynlib: cryptodll.}
proc EVP_des_cfb8*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_cfb8", 
                                       dynlib: cryptodll.}
proc EVP_des_ede_cfb64*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede_cfb64", 
    dynlib: cryptodll.}
proc EVP_des_ede3_cfb64*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_des_ede3_cfb64", dynlib: cryptodll.}
proc EVP_des_ede3_cfb1*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede3_cfb1", 
    dynlib: cryptodll.}
proc EVP_des_ede3_cfb8*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede3_cfb8", 
    dynlib: cryptodll.}
proc EVP_des_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ofb", 
                                      dynlib: cryptodll.}
proc EVP_des_ede_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede_ofb", 
    dynlib: cryptodll.}
proc EVP_des_ede3_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede3_ofb", 
    dynlib: cryptodll.}
proc EVP_des_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_cbc", 
                                      dynlib: cryptodll.}
proc EVP_des_ede_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede_cbc", 
    dynlib: cryptodll.}
proc EVP_des_ede3_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_des_ede3_cbc", 
    dynlib: cryptodll.}
proc EVP_desx_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_desx_cbc", 
                                       dynlib: cryptodll.}
proc EVP_rc4*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc4", dynlib: cryptodll.}
proc EVP_rc4_40*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc4_40", 
                                     dynlib: cryptodll.}
proc EVP_rc4_hmac_md5*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc4_hmac_md5", 
    dynlib: cryptodll.}
proc EVP_idea_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_idea_ecb", 
                                       dynlib: cryptodll.}
proc EVP_idea_cfb64*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_idea_cfb64", 
    dynlib: cryptodll.}
proc EVP_idea_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_idea_ofb", 
                                       dynlib: cryptodll.}
proc EVP_idea_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_idea_cbc", 
                                       dynlib: cryptodll.}
proc EVP_rc2_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc2_ecb", 
                                      dynlib: cryptodll.}
proc EVP_rc2_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc2_cbc", 
                                      dynlib: cryptodll.}
proc EVP_rc2_40_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc2_40_cbc", 
    dynlib: cryptodll.}
proc EVP_rc2_64_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc2_64_cbc", 
    dynlib: cryptodll.}
proc EVP_rc2_cfb64*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc2_cfb64", 
                                        dynlib: cryptodll.}
proc EVP_rc2_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_rc2_ofb", 
                                      dynlib: cryptodll.}
proc EVP_bf_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_bf_ecb", 
                                     dynlib: cryptodll.}
proc EVP_bf_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_bf_cbc", 
                                     dynlib: cryptodll.}
proc EVP_bf_cfb64*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_bf_cfb64", 
                                       dynlib: cryptodll.}
proc EVP_bf_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_bf_ofb", 
                                     dynlib: cryptodll.}
proc EVP_cast5_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_cast5_ecb", 
                                        dynlib: cryptodll.}
proc EVP_cast5_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_cast5_cbc", 
                                        dynlib: cryptodll.}
proc EVP_cast5_cfb64*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_cast5_cfb64", 
    dynlib: cryptodll.}
proc EVP_cast5_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_cast5_ofb", 
                                        dynlib: cryptodll.}
proc EVP_rc5_32_12_16_cbc*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_rc5_32_12_16_cbc", dynlib: cryptodll.}
proc EVP_rc5_32_12_16_ecb*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_rc5_32_12_16_ecb", dynlib: cryptodll.}
proc EVP_rc5_32_12_16_cfb64*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_rc5_32_12_16_cfb64", dynlib: cryptodll.}
proc EVP_rc5_32_12_16_ofb*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_rc5_32_12_16_ofb", dynlib: cryptodll.}
proc EVP_aes_128_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_ecb", 
    dynlib: cryptodll.}
proc EVP_aes_128_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_cbc", 
    dynlib: cryptodll.}
proc EVP_aes_128_cfb1*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_cfb1", 
    dynlib: cryptodll.}
proc EVP_aes_128_cfb8*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_cfb8", 
    dynlib: cryptodll.}
proc EVP_aes_128_cfb128*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_aes_128_cfb128", dynlib: cryptodll.}
proc EVP_aes_128_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_ofb", 
    dynlib: cryptodll.}
proc EVP_aes_128_ctr*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_ctr", 
    dynlib: cryptodll.}
proc EVP_aes_128_ccm*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_ccm", 
    dynlib: cryptodll.}
proc EVP_aes_128_gcm*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_gcm", 
    dynlib: cryptodll.}
proc EVP_aes_128_xts*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_128_xts", 
    dynlib: cryptodll.}
proc EVP_aes_192_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_192_ecb", 
    dynlib: cryptodll.}
proc EVP_aes_192_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_192_cbc", 
    dynlib: cryptodll.}
proc EVP_aes_192_cfb1*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_192_cfb1", 
    dynlib: cryptodll.}
proc EVP_aes_192_cfb8*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_192_cfb8", 
    dynlib: cryptodll.}
proc EVP_aes_192_cfb128*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_aes_192_cfb128", dynlib: cryptodll.}
proc EVP_aes_192_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_192_ofb", 
    dynlib: cryptodll.}
proc EVP_aes_192_ctr*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_192_ctr", 
    dynlib: cryptodll.}
proc EVP_aes_192_ccm*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_192_ccm", 
    dynlib: cryptodll.}
proc EVP_aes_192_gcm*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_192_gcm", 
    dynlib: cryptodll.}
proc EVP_aes_256_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_ecb", 
    dynlib: cryptodll.}
proc EVP_aes_256_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_cbc", 
    dynlib: cryptodll.}
proc EVP_aes_256_cfb1*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_cfb1", 
    dynlib: cryptodll.}
proc EVP_aes_256_cfb8*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_cfb8", 
    dynlib: cryptodll.}
proc EVP_aes_256_cfb128*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_aes_256_cfb128", dynlib: cryptodll.}
proc EVP_aes_256_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_ofb", 
    dynlib: cryptodll.}
proc EVP_aes_256_ctr*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_ctr", 
    dynlib: cryptodll.}
proc EVP_aes_256_ccm*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_ccm", 
    dynlib: cryptodll.}
proc EVP_aes_256_gcm*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_gcm", 
    dynlib: cryptodll.}
proc EVP_aes_256_xts*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_aes_256_xts", 
    dynlib: cryptodll.}
proc EVP_aes_128_cbc_hmac_sha1*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_aes_128_cbc_hmac_sha1", dynlib: cryptodll.}
proc EVP_aes_256_cbc_hmac_sha1*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_aes_256_cbc_hmac_sha1", dynlib: cryptodll.}
proc EVP_camellia_128_ecb*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_128_ecb", dynlib: cryptodll.}
proc EVP_camellia_128_cbc*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_128_cbc", dynlib: cryptodll.}
proc EVP_camellia_128_cfb1*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_128_cfb1", dynlib: cryptodll.}
proc EVP_camellia_128_cfb8*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_128_cfb8", dynlib: cryptodll.}
proc EVP_camellia_128_cfb128*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_128_cfb128", dynlib: cryptodll.}
proc EVP_camellia_128_ofb*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_128_ofb", dynlib: cryptodll.}
proc EVP_camellia_192_ecb*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_192_ecb", dynlib: cryptodll.}
proc EVP_camellia_192_cbc*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_192_cbc", dynlib: cryptodll.}
proc EVP_camellia_192_cfb1*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_192_cfb1", dynlib: cryptodll.}
proc EVP_camellia_192_cfb8*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_192_cfb8", dynlib: cryptodll.}
proc EVP_camellia_192_cfb128*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_192_cfb128", dynlib: cryptodll.}
proc EVP_camellia_192_ofb*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_192_ofb", dynlib: cryptodll.}
proc EVP_camellia_256_ecb*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_256_ecb", dynlib: cryptodll.}
proc EVP_camellia_256_cbc*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_256_cbc", dynlib: cryptodll.}
proc EVP_camellia_256_cfb1*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_256_cfb1", dynlib: cryptodll.}
proc EVP_camellia_256_cfb8*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_256_cfb8", dynlib: cryptodll.}
proc EVP_camellia_256_cfb128*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_256_cfb128", dynlib: cryptodll.}
proc EVP_camellia_256_ofb*(): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_camellia_256_ofb", dynlib: cryptodll.}
proc EVP_seed_ecb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_seed_ecb", 
                                       dynlib: cryptodll.}
proc EVP_seed_cbc*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_seed_cbc", 
                                       dynlib: cryptodll.}
proc EVP_seed_cfb128*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_seed_cfb128", 
    dynlib: cryptodll.}
proc EVP_seed_ofb*(): ptr T_EVP_CIPHER {.cdecl, importc: "EVP_seed_ofb", 
                                       dynlib: cryptodll.}
proc OPENSSL_add_all_algorithms_noconf*() {.cdecl, 
    importc: "OPENSSL_add_all_algorithms_noconf", dynlib: cryptodll.}
proc OPENSSL_add_all_algorithms_conf*() {.cdecl, 
    importc: "OPENSSL_add_all_algorithms_conf", dynlib: cryptodll.}
proc OpenSSL_add_all_ciphers*() {.cdecl, importc: "OpenSSL_add_all_ciphers", 
                                  dynlib: cryptodll.}
proc OpenSSL_add_all_digests*() {.cdecl, importc: "OpenSSL_add_all_digests", 
                                  dynlib: cryptodll.}
proc EVP_add_cipher*(cipher: ptr T_EVP_CIPHER): cint {.cdecl, 
    importc: "EVP_add_cipher", dynlib: cryptodll.}
proc EVP_add_digest*(digest: ptr EVP_MD): cint {.cdecl, 
    importc: "EVP_add_digest", dynlib: cryptodll.}
proc EVP_get_cipherbyname*(name: cstring): ptr T_EVP_CIPHER {.cdecl, 
    importc: "EVP_get_cipherbyname", dynlib: cryptodll.}
proc EVP_get_digestbyname*(name: cstring): ptr EVP_MD {.cdecl, 
    importc: "EVP_get_digestbyname", dynlib: cryptodll.}
proc EVP_cleanup*() {.cdecl, importc: "EVP_cleanup", dynlib: cryptodll.}
proc EVP_CIPHER_do_all*(fn: proc (ciph: ptr T_EVP_CIPHER; frm: cstring; 
                                  to: cstring; x: pointer) {.cdecl.}; 
                        arg: pointer) {.cdecl, importc: "EVP_CIPHER_do_all", 
                                        dynlib: cryptodll.}
proc EVP_CIPHER_do_all_sorted*(fn: proc (ciph: ptr T_EVP_CIPHER; frm: cstring; 
    to: cstring; x: pointer) {.cdecl.}; arg: pointer) {.cdecl, 
    importc: "EVP_CIPHER_do_all_sorted", dynlib: cryptodll.}
proc EVP_MD_do_all*(fn: proc (ciph: ptr EVP_MD; frm: cstring; to: cstring; 
                              x: pointer) {.cdecl.}; arg: pointer) {.cdecl, 
    importc: "EVP_MD_do_all", dynlib: cryptodll.}
proc EVP_MD_do_all_sorted*(fn: proc (ciph: ptr EVP_MD; frm: cstring; 
                                     to: cstring; x: pointer) {.cdecl.}; 
                           arg: pointer) {.cdecl, 
    importc: "EVP_MD_do_all_sorted", dynlib: cryptodll.}
proc EVP_PKEY_decrypt_old*(dec_key: ptr cuchar; enc_key: ptr cuchar; 
                           enc_key_len: cint; private_key: ptr EVP_PKEY): cint {.
    cdecl, importc: "EVP_PKEY_decrypt_old", dynlib: cryptodll.}
proc EVP_PKEY_encrypt_old*(enc_key: ptr cuchar; key: ptr cuchar; key_len: cint; 
                           pub_key: ptr EVP_PKEY): cint {.cdecl, 
    importc: "EVP_PKEY_encrypt_old", dynlib: cryptodll.}
proc EVP_PKEY_type*(typ: cint): cint {.cdecl, importc: "EVP_PKEY_type", 
                                       dynlib: cryptodll.}
proc EVP_PKEY_id*(pkey: ptr EVP_PKEY): cint {.cdecl, importc: "EVP_PKEY_id", 
    dynlib: cryptodll.}
proc EVP_PKEY_base_id*(pkey: ptr EVP_PKEY): cint {.cdecl, 
    importc: "EVP_PKEY_base_id", dynlib: cryptodll.}
proc EVP_PKEY_bits*(pkey: ptr EVP_PKEY): cint {.cdecl, importc: "EVP_PKEY_bits", 
    dynlib: cryptodll.}
proc EVP_PKEY_size*(pkey: ptr EVP_PKEY): cint {.cdecl, importc: "EVP_PKEY_size", 
    dynlib: cryptodll.}
proc EVP_PKEY_set_type*(pkey: ptr EVP_PKEY; typ: cint): cint {.cdecl, 
    importc: "EVP_PKEY_set_type", dynlib: cryptodll.}
proc EVP_PKEY_set_type_str*(pkey: ptr EVP_PKEY; str: cstring; len: cint): cint {.
    cdecl, importc: "EVP_PKEY_set_type_str", dynlib: cryptodll.}
proc EVP_PKEY_assign*(pkey: ptr EVP_PKEY; typ: cint; key: pointer): cint {.
    cdecl, importc: "EVP_PKEY_assign", dynlib: cryptodll.}
proc EVP_PKEY_get0*(pkey: ptr EVP_PKEY): pointer {.cdecl, 
    importc: "EVP_PKEY_get0", dynlib: cryptodll.}


proc EVP_PKEY_set1_RSA*(pkey: ptr EVP_PKEY; key: ptr rsa_st): cint {.cdecl, 
    importc: "EVP_PKEY_set1_RSA", dynlib: cryptodll.}
proc EVP_PKEY_get1_RSA*(pkey: ptr EVP_PKEY): ptr rsa_st {.cdecl, 
    importc: "EVP_PKEY_get1_RSA", dynlib: cryptodll.}

  

proc EVP_PKEY_set1_DSA*(pkey: ptr EVP_PKEY; key: ptr dsa_st): cint {.cdecl, 
    importc: "EVP_PKEY_set1_DSA", dynlib: cryptodll.}
proc EVP_PKEY_get1_DSA*(pkey: ptr EVP_PKEY): ptr dsa_st {.cdecl, 
    importc: "EVP_PKEY_get1_DSA", dynlib: cryptodll.}

  

proc EVP_PKEY_set1_DH*(pkey: ptr EVP_PKEY; key: ptr dh_st): cint {.cdecl, 
    importc: "EVP_PKEY_set1_DH", dynlib: cryptodll.}
proc EVP_PKEY_get1_DH*(pkey: ptr EVP_PKEY): ptr dh_st {.cdecl, 
    importc: "EVP_PKEY_get1_DH", dynlib: cryptodll.}

  

proc EVP_PKEY_set1_EC_KEY*(pkey: ptr EVP_PKEY; key: ptr ec_key_st): cint {.
    cdecl, importc: "EVP_PKEY_set1_EC_KEY", dynlib: cryptodll.}
proc EVP_PKEY_get1_EC_KEY*(pkey: ptr EVP_PKEY): ptr ec_key_st {.cdecl, 
    importc: "EVP_PKEY_get1_EC_KEY", dynlib: cryptodll.}
proc EVP_PKEY_new*(): ptr EVP_PKEY {.cdecl, importc: "EVP_PKEY_new", 
                                     dynlib: cryptodll.}
proc EVP_PKEY_free*(pkey: ptr EVP_PKEY) {.cdecl, importc: "EVP_PKEY_free", 
    dynlib: cryptodll.}
proc d2i_PublicKey*(typ: cint; a: ptr ptr EVP_PKEY; pp: ptr ptr cuchar; 
                    length: clong): ptr EVP_PKEY {.cdecl, 
    importc: "d2i_PublicKey", dynlib: cryptodll.}
proc i2d_PublicKey*(a: ptr EVP_PKEY; pp: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_PublicKey", dynlib: cryptodll.}
proc d2i_PrivateKey*(typ: cint; a: ptr ptr EVP_PKEY; pp: ptr ptr cuchar; 
                     length: clong): ptr EVP_PKEY {.cdecl, 
    importc: "d2i_PrivateKey", dynlib: cryptodll.}
proc d2i_AutoPrivateKey*(a: ptr ptr EVP_PKEY; pp: ptr ptr cuchar; length: clong): ptr EVP_PKEY {.
    cdecl, importc: "d2i_AutoPrivateKey", dynlib: cryptodll.}
proc i2d_PrivateKey*(a: ptr EVP_PKEY; pp: ptr ptr cuchar): cint {.cdecl, 
    importc: "i2d_PrivateKey", dynlib: cryptodll.}
proc EVP_PKEY_copy_parameters*(to: ptr EVP_PKEY; frm: ptr EVP_PKEY): cint {.
    cdecl, importc: "EVP_PKEY_copy_parameters", dynlib: cryptodll.}
proc EVP_PKEY_missing_parameters*(pkey: ptr EVP_PKEY): cint {.cdecl, 
    importc: "EVP_PKEY_missing_parameters", dynlib: cryptodll.}
proc EVP_PKEY_save_parameters*(pkey: ptr EVP_PKEY; mode: cint): cint {.cdecl, 
    importc: "EVP_PKEY_save_parameters", dynlib: cryptodll.}
proc EVP_PKEY_cmp_parameters*(a: ptr EVP_PKEY; b: ptr EVP_PKEY): cint {.cdecl, 
    importc: "EVP_PKEY_cmp_parameters", dynlib: cryptodll.}
proc EVP_PKEY_cmp*(a: ptr EVP_PKEY; b: ptr EVP_PKEY): cint {.cdecl, 
    importc: "EVP_PKEY_cmp", dynlib: cryptodll.}
proc EVP_PKEY_print_public*(output: ptr BIO; pkey: ptr EVP_PKEY; indent: cint; 
                            pctx: ptr ASN1_PCTX): cint {.cdecl, 
    importc: "EVP_PKEY_print_public", dynlib: cryptodll.}
proc EVP_PKEY_print_private*(output: ptr BIO; pkey: ptr EVP_PKEY; indent: cint; 
                             pctx: ptr ASN1_PCTX): cint {.cdecl, 
    importc: "EVP_PKEY_print_private", dynlib: cryptodll.}
proc EVP_PKEY_print_params*(output: ptr BIO; pkey: ptr EVP_PKEY; indent: cint; 
                            pctx: ptr ASN1_PCTX): cint {.cdecl, 
    importc: "EVP_PKEY_print_params", dynlib: cryptodll.}
proc EVP_PKEY_get_default_digest_nid*(pkey: ptr EVP_PKEY; pnid: ptr cint): cint {.
    cdecl, importc: "EVP_PKEY_get_default_digest_nid", dynlib: cryptodll.}
proc EVP_CIPHER_type*(ctx: ptr T_EVP_CIPHER): cint {.cdecl, 
    importc: "EVP_CIPHER_type", dynlib: cryptodll.}
proc EVP_CIPHER_param_to_asn1*(c: ptr EVP_CIPHER_CTX; typ: ptr ASN1_TYPE): cint {.
    cdecl, importc: "EVP_CIPHER_param_to_asn1", dynlib: cryptodll.}
proc EVP_CIPHER_asn1_to_param*(c: ptr EVP_CIPHER_CTX; typ: ptr ASN1_TYPE): cint {.
    cdecl, importc: "EVP_CIPHER_asn1_to_param", dynlib: cryptodll.}
proc EVP_CIPHER_set_asn1_iv*(c: ptr EVP_CIPHER_CTX; typ: ptr ASN1_TYPE): cint {.
    cdecl, importc: "EVP_CIPHER_set_asn1_iv", dynlib: cryptodll.}
proc EVP_CIPHER_get_asn1_iv*(c: ptr EVP_CIPHER_CTX; typ: ptr ASN1_TYPE): cint {.
    cdecl, importc: "EVP_CIPHER_get_asn1_iv", dynlib: cryptodll.}
proc PKCS5_PBE_keyivgen*(ctx: ptr EVP_CIPHER_CTX; pass: cstring; passlen: cint; 
                         param: ptr ASN1_TYPE; cipher: ptr T_EVP_CIPHER; 
                         md: ptr EVP_MD; en_de: cint): cint {.cdecl, 
    importc: "PKCS5_PBE_keyivgen", dynlib: cryptodll.}
proc PKCS5_PBKDF2_HMAC_SHA1*(pass: cstring; passlen: cint; salt: ptr cuchar; 
                             saltlen: cint; iter: cint; keylen: cint; 
                             output: ptr cuchar): cint {.cdecl, 
    importc: "PKCS5_PBKDF2_HMAC_SHA1", dynlib: cryptodll.}
proc PKCS5_PBKDF2_HMAC*(pass: cstring; passlen: cint; salt: ptr cuchar; 
                        saltlen: cint; iter: cint; digest: ptr EVP_MD; 
                        keylen: cint; output: ptr cuchar): cint {.cdecl, 
    importc: "PKCS5_PBKDF2_HMAC", dynlib: cryptodll.}
proc PKCS5_v2_PBE_keyivgen*(ctx: ptr EVP_CIPHER_CTX; pass: cstring; 
                            passlen: cint; param: ptr ASN1_TYPE; 
                            cipher: ptr T_EVP_CIPHER; md: ptr EVP_MD; en_de: cint): cint {.
    cdecl, importc: "PKCS5_v2_PBE_keyivgen", dynlib: cryptodll.}
proc PKCS5_PBE_add*() {.cdecl, importc: "PKCS5_PBE_add", dynlib: cryptodll.}
proc EVP_PBE_CipherInit*(pbe_obj: ptr ASN1_OBJECT; pass: cstring; passlen: cint; 
                         param: ptr ASN1_TYPE; ctx: ptr EVP_CIPHER_CTX; 
                         en_de: cint): cint {.cdecl, 
    importc: "EVP_PBE_CipherInit", dynlib: cryptodll.}
# PBE type 
# Can appear as the outermost AlgorithmIdentifier 

const 
  EVP_PBE_TYPE_OUTER* = 0x00000000

# Is an PRF type OID 

const 
  EVP_PBE_TYPE_PRF* = 0x00000001

proc EVP_PBE_alg_add_type*(pbe_type: cint; pbe_nid: cint; cipher_nid: cint; 
                           md_nid: cint; keygen: ptr EVP_PBE_KEYGEN): cint {.
    cdecl, importc: "EVP_PBE_alg_add_type", dynlib: cryptodll.}
proc EVP_PBE_alg_add*(nid: cint; cipher: ptr T_EVP_CIPHER; md: ptr EVP_MD; 
                      keygen: ptr EVP_PBE_KEYGEN): cint {.cdecl, 
    importc: "EVP_PBE_alg_add", dynlib: cryptodll.}
proc EVP_PBE_find*(typ: cint; pbe_nid: cint; pcnid: ptr cint; pmnid: ptr cint; 
                   pkeygen: ptr ptr EVP_PBE_KEYGEN): cint {.cdecl, 
    importc: "EVP_PBE_find", dynlib: cryptodll.}
proc EVP_PBE_cleanup*() {.cdecl, importc: "EVP_PBE_cleanup", dynlib: cryptodll.}
const 
  ASN1_PKEY_ALIAS* = 0x00000001
  ASN1_PKEY_DYNAMIC* = 0x00000002
  ASN1_PKEY_SIGPARAM_NULL* = 0x00000004
  ASN1_PKEY_CTRL_PKCS7_SIGN* = 0x00000001
  ASN1_PKEY_CTRL_PKCS7_ENCRYPT* = 0x00000002
  ASN1_PKEY_CTRL_DEFAULT_MD_NID* = 0x00000003
  ASN1_PKEY_CTRL_CMS_SIGN* = 0x00000005
  ASN1_PKEY_CTRL_CMS_ENVELOPE* = 0x00000007

proc EVP_PKEY_asn1_get_count*(): cint {.cdecl, 
                                        importc: "EVP_PKEY_asn1_get_count", 
                                        dynlib: cryptodll.}
proc EVP_PKEY_asn1_get0*(idx: cint): ptr EVP_PKEY_ASN1_METHOD {.cdecl, 
    importc: "EVP_PKEY_asn1_get0", dynlib: cryptodll.}
proc EVP_PKEY_asn1_find*(pe: ptr ptr ENGINE; typ: cint): ptr EVP_PKEY_ASN1_METHOD {.
    cdecl, importc: "EVP_PKEY_asn1_find", dynlib: cryptodll.}
proc EVP_PKEY_asn1_find_str*(pe: ptr ptr ENGINE; str: cstring; len: cint): ptr EVP_PKEY_ASN1_METHOD {.
    cdecl, importc: "EVP_PKEY_asn1_find_str", dynlib: cryptodll.}
proc EVP_PKEY_asn1_add0*(ameth: ptr EVP_PKEY_ASN1_METHOD): cint {.cdecl, 
    importc: "EVP_PKEY_asn1_add0", dynlib: cryptodll.}
proc EVP_PKEY_asn1_add_alias*(to: cint; frm: cint): cint {.cdecl, 
    importc: "EVP_PKEY_asn1_add_alias", dynlib: cryptodll.}
proc EVP_PKEY_asn1_get0_info*(ppkey_id: ptr cint; pkey_base_id: ptr cint; 
                              ppkey_flags: ptr cint; pinfo: cstringArray; 
                              ppem_str: cstringArray; 
                              ameth: ptr EVP_PKEY_ASN1_METHOD): cint {.cdecl, 
    importc: "EVP_PKEY_asn1_get0_info", dynlib: cryptodll.}
proc EVP_PKEY_get0_asn1*(pkey: ptr EVP_PKEY): ptr EVP_PKEY_ASN1_METHOD {.cdecl, 
    importc: "EVP_PKEY_get0_asn1", dynlib: cryptodll.}
proc EVP_PKEY_asn1_new*(id: cint; flags: cint; pem_str: cstring; info: cstring): ptr EVP_PKEY_ASN1_METHOD {.
    cdecl, importc: "EVP_PKEY_asn1_new", dynlib: cryptodll.}
proc EVP_PKEY_asn1_copy*(dst: ptr EVP_PKEY_ASN1_METHOD; 
                         src: ptr EVP_PKEY_ASN1_METHOD) {.cdecl, 
    importc: "EVP_PKEY_asn1_copy", dynlib: cryptodll.}
proc EVP_PKEY_asn1_free*(ameth: ptr EVP_PKEY_ASN1_METHOD) {.cdecl, 
    importc: "EVP_PKEY_asn1_free", dynlib: cryptodll.}
proc EVP_PKEY_asn1_set_public*(ameth: ptr EVP_PKEY_ASN1_METHOD; pub_decode: proc (
    pk: ptr EVP_PKEY; pub: ptr X509_PUBKEY): cint {.cdecl.}; pub_encode: proc (
    pub: ptr X509_PUBKEY; pk: ptr EVP_PKEY): cint {.cdecl.}; pub_cmp: proc (
    a: ptr EVP_PKEY; b: ptr EVP_PKEY): cint {.cdecl.}; pub_print: proc (
    output: ptr BIO; pkey: ptr EVP_PKEY; indent: cint; pctx: ptr ASN1_PCTX): cint {.
    cdecl.}; pkey_size: proc (pk: ptr EVP_PKEY): cint {.cdecl.}; pkey_bits: proc (
    pk: ptr EVP_PKEY): cint {.cdecl.}) {.cdecl, 
    importc: "EVP_PKEY_asn1_set_public", dynlib: cryptodll.}
proc EVP_PKEY_asn1_set_private*(ameth: ptr EVP_PKEY_ASN1_METHOD; priv_decode: proc (
    pk: ptr EVP_PKEY; p8inf: ptr PKCS8_PRIV_KEY_INFO): cint {.cdecl.}; 
    priv_encode: proc (p8: ptr PKCS8_PRIV_KEY_INFO; pk: ptr EVP_PKEY): cint {.
    cdecl.}; priv_print: proc (output: ptr BIO; pkey: ptr EVP_PKEY; 
                               indent: cint; pctx: ptr ASN1_PCTX): cint {.cdecl.}) {.
    cdecl, importc: "EVP_PKEY_asn1_set_private", dynlib: cryptodll.}
proc EVP_PKEY_asn1_set_param*(ameth: ptr EVP_PKEY_ASN1_METHOD; param_decode: proc (
    pkey: ptr EVP_PKEY; pder: ptr ptr cuchar; derlen: cint): cint {.cdecl.}; 
    param_encode: proc (pkey: ptr EVP_PKEY; pder: ptr ptr cuchar): cint {.cdecl.}; 
    param_missing: proc (pk: ptr EVP_PKEY): cint {.cdecl.}; param_copy: proc (
    to: ptr EVP_PKEY; frm: ptr EVP_PKEY): cint {.cdecl.}; param_cmp: proc (
    a: ptr EVP_PKEY; b: ptr EVP_PKEY): cint {.cdecl.}; param_print: proc (
    output: ptr BIO; pkey: ptr EVP_PKEY; indent: cint; pctx: ptr ASN1_PCTX): cint {.
    cdecl.}) {.cdecl, importc: "EVP_PKEY_asn1_set_param", dynlib: cryptodll.}
proc EVP_PKEY_asn1_set_free*(ameth: ptr EVP_PKEY_ASN1_METHOD; 
                             pkey_free: proc (pkey: ptr EVP_PKEY) {.cdecl.}) {.
    cdecl, importc: "EVP_PKEY_asn1_set_free", dynlib: cryptodll.}
proc EVP_PKEY_asn1_set_ctrl*(ameth: ptr EVP_PKEY_ASN1_METHOD; pkey_ctrl: proc (
    pkey: ptr EVP_PKEY; op: cint; arg1: clong; arg2: pointer): cint {.cdecl.}) {.
    cdecl, importc: "EVP_PKEY_asn1_set_ctrl", dynlib: cryptodll.}
const 
  EVP_PKEY_OP_UNDEFINED* = 0
  EVP_PKEY_OP_PARAMGEN* = (1 shl 1)
  EVP_PKEY_OP_KEYGEN* = (1 shl 2)
  EVP_PKEY_OP_SIGN* = (1 shl 3)
  EVP_PKEY_OP_VERIFY* = (1 shl 4)
  EVP_PKEY_OP_VERIFYRECOVER* = (1 shl 5)
  EVP_PKEY_OP_SIGNCTX* = (1 shl 6)
  EVP_PKEY_OP_VERIFYCTX* = (1 shl 7)
  EVP_PKEY_OP_ENCRYPT* = (1 shl 8)
  EVP_PKEY_OP_DECRYPT* = (1 shl 9)
  EVP_PKEY_OP_DERIVE* = (1 shl 10)
let
  EVP_PKEY_OP_TYPE_SIG* = (EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY or
      EVP_PKEY_OP_VERIFYRECOVER or EVP_PKEY_OP_SIGNCTX or
      EVP_PKEY_OP_VERIFYCTX)
  EVP_PKEY_OP_TYPE_CRYPT* = (EVP_PKEY_OP_ENCRYPT or EVP_PKEY_OP_DECRYPT)
  # FIXME: These don't seem to be defined...
  #EVP_PKEY_OP_TYPE_NOGEN* = (
  #  EVP_PKEY_OP_SIG or EVP_PKEY_OP_CRYPT or EVP_PKEY_OP_DERIVE)
  EVP_PKEY_OP_TYPE_GEN* = (EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN)

template EVP_PKEY_CTX_set_signature_md*(ctx, md: expr): expr = 
  EVP_PKEY_CTX_ctrl(ctx, - 1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD, 0, 
                    cast[pointer](md))

const 
  EVP_PKEY_CTRL_MD* = 1
  EVP_PKEY_CTRL_PEER_KEY* = 2
  EVP_PKEY_CTRL_PKCS7_ENCRYPT* = 3
  EVP_PKEY_CTRL_PKCS7_DECRYPT* = 4
  EVP_PKEY_CTRL_PKCS7_SIGN* = 5
  EVP_PKEY_CTRL_SET_MAC_KEY* = 6
  EVP_PKEY_CTRL_DIGESTINIT* = 7

# Used by GOST key encryption in TLS 

const 
  EVP_PKEY_CTRL_SET_IV* = 8
  EVP_PKEY_CTRL_CMS_ENCRYPT* = 9
  EVP_PKEY_CTRL_CMS_DECRYPT* = 10
  EVP_PKEY_CTRL_CMS_SIGN* = 11
  EVP_PKEY_CTRL_CIPHER* = 12
  EVP_PKEY_ALG_CTRL* = 0x00001000
  EVP_PKEY_FLAG_AUTOARGLEN* = 2

# Method handles all operations: don't assume any digest related
#  defaults.
# 

const 
  EVP_PKEY_FLAG_SIGCTX_CUSTOM* = 4

proc EVP_PKEY_meth_find*(typ: cint): ptr EVP_PKEY_METHOD {.cdecl, 
    importc: "EVP_PKEY_meth_find", dynlib: cryptodll.}
proc EVP_PKEY_meth_new*(id: cint; flags: cint): ptr EVP_PKEY_METHOD {.cdecl, 
    importc: "EVP_PKEY_meth_new", dynlib: cryptodll.}
proc EVP_PKEY_meth_get0_info*(ppkey_id: ptr cint; pflags: ptr cint; 
                              meth: ptr EVP_PKEY_METHOD) {.cdecl, 
    importc: "EVP_PKEY_meth_get0_info", dynlib: cryptodll.}
proc EVP_PKEY_meth_copy*(dst: ptr EVP_PKEY_METHOD; src: ptr EVP_PKEY_METHOD) {.
    cdecl, importc: "EVP_PKEY_meth_copy", dynlib: cryptodll.}
proc EVP_PKEY_meth_free*(pmeth: ptr EVP_PKEY_METHOD) {.cdecl, 
    importc: "EVP_PKEY_meth_free", dynlib: cryptodll.}
proc EVP_PKEY_meth_add0*(pmeth: ptr EVP_PKEY_METHOD): cint {.cdecl, 
    importc: "EVP_PKEY_meth_add0", dynlib: cryptodll.}
proc EVP_PKEY_CTX_new*(pkey: ptr EVP_PKEY; e: ptr ENGINE): ptr EVP_PKEY_CTX {.
    cdecl, importc: "EVP_PKEY_CTX_new", dynlib: cryptodll.}
proc EVP_PKEY_CTX_new_id*(id: cint; e: ptr ENGINE): ptr EVP_PKEY_CTX {.cdecl, 
    importc: "EVP_PKEY_CTX_new_id", dynlib: cryptodll.}
proc EVP_PKEY_CTX_dup*(ctx: ptr EVP_PKEY_CTX): ptr EVP_PKEY_CTX {.cdecl, 
    importc: "EVP_PKEY_CTX_dup", dynlib: cryptodll.}
proc EVP_PKEY_CTX_free*(ctx: ptr EVP_PKEY_CTX) {.cdecl, 
    importc: "EVP_PKEY_CTX_free", dynlib: cryptodll.}
proc EVP_PKEY_CTX_ctrl*(ctx: ptr EVP_PKEY_CTX; keytype: cint; optype: cint; 
                        cmd: cint; p1: cint; p2: pointer): cint {.cdecl, 
    importc: "EVP_PKEY_CTX_ctrl", dynlib: cryptodll.}
proc EVP_PKEY_CTX_ctrl_str*(ctx: ptr EVP_PKEY_CTX; typ: cstring; value: cstring): cint {.
    cdecl, importc: "EVP_PKEY_CTX_ctrl_str", dynlib: cryptodll.}
proc EVP_PKEY_CTX_get_operation*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_CTX_get_operation", dynlib: cryptodll.}
proc EVP_PKEY_CTX_set0_keygen_info*(ctx: ptr EVP_PKEY_CTX; dat: ptr cint; 
                                    datlen: cint) {.cdecl, 
    importc: "EVP_PKEY_CTX_set0_keygen_info", dynlib: cryptodll.}
proc EVP_PKEY_new_mac_key*(typ: cint; e: ptr ENGINE; key: ptr cuchar; 
                           keylen: cint): ptr EVP_PKEY {.cdecl, 
    importc: "EVP_PKEY_new_mac_key", dynlib: cryptodll.}
proc EVP_PKEY_CTX_set_data*(ctx: ptr EVP_PKEY_CTX; data: pointer) {.cdecl, 
    importc: "EVP_PKEY_CTX_set_data", dynlib: cryptodll.}
proc EVP_PKEY_CTX_get_data*(ctx: ptr EVP_PKEY_CTX): pointer {.cdecl, 
    importc: "EVP_PKEY_CTX_get_data", dynlib: cryptodll.}
proc EVP_PKEY_CTX_get0_pkey*(ctx: ptr EVP_PKEY_CTX): ptr EVP_PKEY {.cdecl, 
    importc: "EVP_PKEY_CTX_get0_pkey", dynlib: cryptodll.}
proc EVP_PKEY_CTX_get0_peerkey*(ctx: ptr EVP_PKEY_CTX): ptr EVP_PKEY {.cdecl, 
    importc: "EVP_PKEY_CTX_get0_peerkey", dynlib: cryptodll.}
proc EVP_PKEY_CTX_set_app_data*(ctx: ptr EVP_PKEY_CTX; data: pointer) {.cdecl, 
    importc: "EVP_PKEY_CTX_set_app_data", dynlib: cryptodll.}
proc EVP_PKEY_CTX_get_app_data*(ctx: ptr EVP_PKEY_CTX): pointer {.cdecl, 
    importc: "EVP_PKEY_CTX_get_app_data", dynlib: cryptodll.}
proc EVP_PKEY_sign_init*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_sign_init", dynlib: cryptodll.}
proc EVP_PKEY_sign*(ctx: ptr EVP_PKEY_CTX; sig: ptr cuchar; siglen: ptr csize; 
                    tbs: ptr cuchar; tbslen: csize): cint {.cdecl, 
    importc: "EVP_PKEY_sign", dynlib: cryptodll.}
proc EVP_PKEY_verify_init*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_verify_init", dynlib: cryptodll.}
proc EVP_PKEY_verify*(ctx: ptr EVP_PKEY_CTX; sig: ptr cuchar; siglen: csize; 
                      tbs: ptr cuchar; tbslen: csize): cint {.cdecl, 
    importc: "EVP_PKEY_verify", dynlib: cryptodll.}
proc EVP_PKEY_verify_recover_init*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_verify_recover_init", dynlib: cryptodll.}
proc EVP_PKEY_verify_recover*(ctx: ptr EVP_PKEY_CTX; rout: ptr cuchar; 
                              routlen: ptr csize; sig: ptr cuchar; siglen: csize): cint {.
    cdecl, importc: "EVP_PKEY_verify_recover", dynlib: cryptodll.}
proc EVP_PKEY_encrypt_init*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_encrypt_init", dynlib: cryptodll.}
proc EVP_PKEY_encrypt*(ctx: ptr EVP_PKEY_CTX; output: ptr cuchar; 
                       outlen: ptr csize; input: ptr cuchar; inlen: csize): cint {.
    cdecl, importc: "EVP_PKEY_encrypt", dynlib: cryptodll.}
proc EVP_PKEY_decrypt_init*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_decrypt_init", dynlib: cryptodll.}
proc EVP_PKEY_decrypt*(ctx: ptr EVP_PKEY_CTX; output: ptr cuchar; 
                       outlen: ptr csize; input: ptr cuchar; inlen: csize): cint {.
    cdecl, importc: "EVP_PKEY_decrypt", dynlib: cryptodll.}
proc EVP_PKEY_derive_init*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_derive_init", dynlib: cryptodll.}
proc EVP_PKEY_derive_set_peer*(ctx: ptr EVP_PKEY_CTX; peer: ptr EVP_PKEY): cint {.
    cdecl, importc: "EVP_PKEY_derive_set_peer", dynlib: cryptodll.}
proc EVP_PKEY_derive*(ctx: ptr EVP_PKEY_CTX; key: ptr cuchar; keylen: ptr csize): cint {.
    cdecl, importc: "EVP_PKEY_derive", dynlib: cryptodll.}
type 
  EVP_PKEY_gen_cb* = proc (ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}

proc EVP_PKEY_paramgen_init*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_paramgen_init", dynlib: cryptodll.}
proc EVP_PKEY_paramgen*(ctx: ptr EVP_PKEY_CTX; ppkey: ptr ptr EVP_PKEY): cint {.
    cdecl, importc: "EVP_PKEY_paramgen", dynlib: cryptodll.}
proc EVP_PKEY_keygen_init*(ctx: ptr EVP_PKEY_CTX): cint {.cdecl, 
    importc: "EVP_PKEY_keygen_init", dynlib: cryptodll.}
proc EVP_PKEY_keygen*(ctx: ptr EVP_PKEY_CTX; ppkey: ptr ptr EVP_PKEY): cint {.
    cdecl, importc: "EVP_PKEY_keygen", dynlib: cryptodll.}
proc EVP_PKEY_CTX_set_cb*(ctx: ptr EVP_PKEY_CTX; cb: ptr EVP_PKEY_gen_cb) {.
    cdecl, importc: "EVP_PKEY_CTX_set_cb", dynlib: cryptodll.}
proc EVP_PKEY_CTX_get_cb*(ctx: ptr EVP_PKEY_CTX): ptr EVP_PKEY_gen_cb {.cdecl, 
    importc: "EVP_PKEY_CTX_get_cb", dynlib: cryptodll.}
proc EVP_PKEY_CTX_get_keygen_info*(ctx: ptr EVP_PKEY_CTX; idx: cint): cint {.
    cdecl, importc: "EVP_PKEY_CTX_get_keygen_info", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_init*(pmeth: ptr EVP_PKEY_METHOD; 
                             init: proc (ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}) {.
    cdecl, importc: "EVP_PKEY_meth_set_init", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_copy*(pmeth: ptr EVP_PKEY_METHOD; copy: proc (
    dst: ptr EVP_PKEY_CTX; src: ptr EVP_PKEY_CTX): cint {.cdecl.}) {.cdecl, 
    importc: "EVP_PKEY_meth_set_copy", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_cleanup*(pmeth: ptr EVP_PKEY_METHOD; 
                                cleanup: proc (ctx: ptr EVP_PKEY_CTX) {.cdecl.}) {.
    cdecl, importc: "EVP_PKEY_meth_set_cleanup", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_paramgen*(pmeth: ptr EVP_PKEY_METHOD; paramgen_init: proc (
    ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}; paramgen: proc (
    ctx: ptr EVP_PKEY_CTX; pkey: ptr EVP_PKEY): cint {.cdecl.}) {.cdecl, 
    importc: "EVP_PKEY_meth_set_paramgen", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_keygen*(pmeth: ptr EVP_PKEY_METHOD; keygen_init: proc (
    ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}; keygen: proc (ctx: ptr EVP_PKEY_CTX; 
    pkey: ptr EVP_PKEY): cint {.cdecl.}) {.cdecl, 
    importc: "EVP_PKEY_meth_set_keygen", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_sign*(pmeth: ptr EVP_PKEY_METHOD; sign_init: proc (
    ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}; sign: proc (ctx: ptr EVP_PKEY_CTX; 
    sig: ptr cuchar; siglen: ptr csize; tbs: ptr cuchar; tbslen: csize): cint {.
    cdecl.}) {.cdecl, importc: "EVP_PKEY_meth_set_sign", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_verify*(pmeth: ptr EVP_PKEY_METHOD; verify_init: proc (
    ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}; verify: proc (ctx: ptr EVP_PKEY_CTX; 
    sig: ptr cuchar; siglen: csize; tbs: ptr cuchar; tbslen: csize): cint {.
    cdecl.}) {.cdecl, importc: "EVP_PKEY_meth_set_verify", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_verify_recover*(pmeth: ptr EVP_PKEY_METHOD; 
    verify_recover_init: proc (ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}; 
    verify_recover: proc (ctx: ptr EVP_PKEY_CTX; sig: ptr cuchar; 
                          siglen: ptr csize; tbs: ptr cuchar; tbslen: csize): cint {.
    cdecl.}) {.cdecl, importc: "EVP_PKEY_meth_set_verify_recover", 
               dynlib: cryptodll.}
proc EVP_PKEY_meth_set_signctx*(pmeth: ptr EVP_PKEY_METHOD; signctx_init: proc (
    ctx: ptr EVP_PKEY_CTX; mctx: ptr EVP_MD_CTX): cint {.cdecl.}; signctx: proc (
    ctx: ptr EVP_PKEY_CTX; sig: ptr cuchar; siglen: ptr csize; 
    mctx: ptr EVP_MD_CTX): cint {.cdecl.}) {.cdecl, 
    importc: "EVP_PKEY_meth_set_signctx", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_verifyctx*(pmeth: ptr EVP_PKEY_METHOD; verifyctx_init: proc (
    ctx: ptr EVP_PKEY_CTX; mctx: ptr EVP_MD_CTX): cint {.cdecl.}; verifyctx: proc (
    ctx: ptr EVP_PKEY_CTX; sig: ptr cuchar; siglen: cint; mctx: ptr EVP_MD_CTX): cint {.
    cdecl.}) {.cdecl, importc: "EVP_PKEY_meth_set_verifyctx", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_encrypt*(pmeth: ptr EVP_PKEY_METHOD; encrypt_init: proc (
    ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}; encryptfn: proc (
    ctx: ptr EVP_PKEY_CTX; output: ptr cuchar; outlen: ptr csize; 
    input: ptr cuchar; inlen: csize): cint {.cdecl.}) {.cdecl, 
    importc: "EVP_PKEY_meth_set_encrypt", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_decrypt*(pmeth: ptr EVP_PKEY_METHOD; decrypt_init: proc (
    ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}; decrypt: proc (
    ctx: ptr EVP_PKEY_CTX; output: ptr cuchar; outlen: ptr csize; 
    input: ptr cuchar; inlen: csize): cint {.cdecl.}) {.cdecl, 
    importc: "EVP_PKEY_meth_set_decrypt", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_derive*(pmeth: ptr EVP_PKEY_METHOD; derive_init: proc (
    ctx: ptr EVP_PKEY_CTX): cint {.cdecl.}; derive: proc (ctx: ptr EVP_PKEY_CTX; 
    key: ptr cuchar; keylen: ptr csize): cint {.cdecl.}) {.cdecl, 
    importc: "EVP_PKEY_meth_set_derive", dynlib: cryptodll.}
proc EVP_PKEY_meth_set_ctrl*(pmeth: ptr EVP_PKEY_METHOD; ctrl: proc (
    ctx: ptr EVP_PKEY_CTX; typ: cint; p1: cint; p2: pointer): cint {.cdecl.}; 
    ctrl_str: proc (ctx: ptr EVP_PKEY_CTX; typ: cstring; value: cstring): cint {.
    cdecl.}) {.cdecl, importc: "EVP_PKEY_meth_set_ctrl", dynlib: cryptodll.}
proc EVP_add_alg_module*() {.cdecl, importc: "EVP_add_alg_module", 
                             dynlib: cryptodll.}
proc ERR_load_EVP_strings*() {.cdecl, importc: "ERR_load_EVP_strings", 
                               dynlib: cryptodll.}
# Error codes for the EVP functions. 
# Function codes. 

const 
  EVP_F_AESNI_INIT_KEY* = 165
  EVP_F_AESNI_XTS_CIPHER* = 176
  EVP_F_AES_INIT_KEY* = 133
  EVP_F_AES_XTS* = 172
  EVP_F_AES_XTS_CIPHER* = 175
  EVP_F_ALG_MODULE_INIT* = 177
  EVP_F_CAMELLIA_INIT_KEY* = 159
  EVP_F_CMAC_INIT* = 173
  EVP_F_D2I_PKEY* = 100
  EVP_F_DO_SIGVER_INIT* = 161
  EVP_F_DSAPKEY2PKCS8* = 134
  # added _2 to:
  EVP_F_DSA_PKEY2PKCS8_2* = 135
  EVP_F_ECDSA_PKEY2PKCS8* = 129
  EVP_F_ECKEY_PKEY2PKCS8* = 132
  EVP_F_EVP_CIPHERINIT_EX* = 123
  EVP_F_EVP_CIPHER_CTX_COPY* = 163
  EVP_F_EVP_CIPHER_CTX_CTRL* = 124
  EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH* = 122
  EVP_F_EVP_DECRYPTFINAL_EX* = 101
  EVP_F_EVP_DIGESTINIT_EX* = 128
  EVP_F_EVP_ENCRYPTFINAL_EX* = 127
  EVP_F_EVP_MD_CTX_COPY_EX* = 110
  EVP_F_EVP_MD_SIZE* = 162
  EVP_F_EVP_OPENINIT* = 102
  EVP_F_EVP_PBE_ALG_ADD* = 115
  EVP_F_EVP_PBE_ALG_ADD_TYPE* = 160
  EVP_F_EVP_PBE_CIPHERINIT* = 116
  EVP_F_EVP_PKCS82PKEY* = 111
  EVP_F_EVP_PKCS82PKEY_BROKEN* = 136
  EVP_F_EVP_PKEY2PKCS8_BROKEN* = 113
  EVP_F_EVP_PKEY_COPY_PARAMETERS* = 103
  EVP_F_EVP_PKEY_CTX_CTRL* = 137
  EVP_F_EVP_PKEY_CTX_CTRL_STR* = 150
  EVP_F_EVP_PKEY_CTX_DUP* = 156
  EVP_F_EVP_PKEY_DECRYPT* = 104
  EVP_F_EVP_PKEY_DECRYPT_INIT* = 138
  EVP_F_EVP_PKEY_DECRYPT_OLD* = 151
  EVP_F_EVP_PKEY_DERIVE* = 153
  EVP_F_EVP_PKEY_DERIVE_INIT* = 154
  EVP_F_EVP_PKEY_DERIVE_SET_PEER* = 155
  EVP_F_EVP_PKEY_ENCRYPT* = 105
  EVP_F_EVP_PKEY_ENCRYPT_INIT* = 139
  EVP_F_EVP_PKEY_ENCRYPT_OLD* = 152
  EVP_F_EVP_PKEY_GET1_DH* = 119
  EVP_F_EVP_PKEY_GET1_DSA* = 120
  EVP_F_EVP_PKEY_GET1_ECDSA* = 130
  EVP_F_EVP_PKEY_GET1_EC_KEY* = 131
  EVP_F_EVP_PKEY_GET1_RSA* = 121
  EVP_F_EVP_PKEY_KEYGEN* = 146
  EVP_F_EVP_PKEY_KEYGEN_INIT* = 147
  EVP_F_EVP_PKEY_NEW* = 106
  EVP_F_EVP_PKEY_PARAMGEN* = 148
  EVP_F_EVP_PKEY_PARAMGEN_INIT* = 149
  EVP_F_EVP_PKEY_SIGN* = 140
  EVP_F_EVP_PKEY_SIGN_INIT* = 141
  EVP_F_EVP_PKEY_VERIFY* = 142
  EVP_F_EVP_PKEY_VERIFY_INIT* = 143
  EVP_F_EVP_PKEY_VERIFY_RECOVER* = 144
  EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT* = 145
  EVP_F_EVP_RIJNDAEL* = 126
  EVP_F_EVP_SIGNFINAL* = 107
  EVP_F_EVP_VERIFYFINAL* = 108
  EVP_F_FIPS_CIPHERINIT* = 166
  EVP_F_FIPS_CIPHER_CTX_COPY* = 170
  EVP_F_FIPS_CIPHER_CTX_CTRL* = 167
  EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH* = 171
  EVP_F_FIPS_DIGESTINIT* = 168
  EVP_F_FIPS_MD_CTX_COPY* = 169
  EVP_F_HMAC_INIT_EX* = 174
  EVP_F_INT_CTX_NEW* = 157
  EVP_F_PKCS5_PBE_KEYIVGEN* = 117
  EVP_F_PKCS5_V2_PBE_KEYIVGEN* = 118
  EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN* = 164
  EVP_F_PKCS8_SET_BROKEN* = 112
  EVP_F_PKEY_SET_TYPE* = 158
  EVP_F_RC2_MAGIC_TO_METH* = 109
  EVP_F_RC5_CTRL* = 125

# Reason codes. 

const 
  EVP_R_AES_IV_SETUP_FAILED* = 162
  EVP_R_AES_KEY_SETUP_FAILED* = 143
  EVP_R_ASN1_LIB* = 140
  EVP_R_BAD_BLOCK_LENGTH* = 136
  EVP_R_BAD_DECRYPT* = 100
  EVP_R_BAD_KEY_LENGTH* = 137
  EVP_R_BN_DECODE_ERROR* = 112
  EVP_R_BN_PUBKEY_ERROR* = 113
  EVP_R_BUFFER_TOO_SMALL* = 155
  EVP_R_CAMELLIA_KEY_SETUP_FAILED* = 157
  EVP_R_CIPHER_PARAMETER_ERROR* = 122
  EVP_R_COMMAND_NOT_SUPPORTED* = 147
  EVP_R_CTRL_NOT_IMPLEMENTED* = 132
  EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED* = 133
  EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH* = 138
  EVP_R_DECODE_ERROR* = 114
  EVP_R_DIFFERENT_KEY_TYPES* = 101
  EVP_R_DIFFERENT_PARAMETERS* = 153
  EVP_R_DISABLED_FOR_FIPS* = 163
  EVP_R_ENCODE_ERROR* = 115
  EVP_R_ERROR_LOADING_SECTION* = 165
  EVP_R_ERROR_SETTING_FIPS_MODE* = 166
  EVP_R_EVP_PBE_CIPHERINIT_ERROR* = 119
  EVP_R_EXPECTING_AN_RSA_KEY* = 127
  EVP_R_EXPECTING_A_DH_KEY* = 128
  EVP_R_EXPECTING_A_DSA_KEY* = 129
  EVP_R_EXPECTING_A_ECDSA_KEY* = 141
  EVP_R_EXPECTING_A_EC_KEY* = 142
  EVP_R_FIPS_MODE_NOT_SUPPORTED* = 167
  EVP_R_INITIALIZATION_ERROR* = 134
  EVP_R_INPUT_NOT_INITIALIZED* = 111
  EVP_R_INVALID_DIGEST* = 152
  EVP_R_INVALID_FIPS_MODE* = 168
  EVP_R_INVALID_KEY_LENGTH* = 130
  EVP_R_INVALID_OPERATION* = 148
  EVP_R_IV_TOO_LARGE* = 102
  EVP_R_KEYGEN_FAILURE* = 120
  EVP_R_MESSAGE_DIGEST_IS_NULL* = 159
  EVP_R_METHOD_NOT_SUPPORTED* = 144
  EVP_R_MISSING_PARAMETERS* = 103
  EVP_R_NO_CIPHER_SET* = 131
  EVP_R_NO_DEFAULT_DIGEST* = 158
  EVP_R_NO_DIGEST_SET* = 139
  EVP_R_NO_DSA_PARAMETERS* = 116
  EVP_R_NO_KEY_SET* = 154
  EVP_R_NO_OPERATION_SET* = 149
  EVP_R_NO_SIGN_FUNCTION_CONFIGURED* = 104
  EVP_R_NO_VERIFY_FUNCTION_CONFIGURED* = 105
  EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE* = 150
  EVP_R_OPERATON_NOT_INITIALIZED* = 151
  EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE* = 117
  EVP_R_PRIVATE_KEY_DECODE_ERROR* = 145
  EVP_R_PRIVATE_KEY_ENCODE_ERROR* = 146
  EVP_R_PUBLIC_KEY_NOT_RSA* = 106
  EVP_R_TOO_LARGE* = 164
  EVP_R_UNKNOWN_CIPHER* = 160
  EVP_R_UNKNOWN_DIGEST* = 161
  EVP_R_UNKNOWN_OPTION* = 169
  EVP_R_UNKNOWN_PBE_ALGORITHM* = 121
  EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS* = 135
  EVP_R_UNSUPPORTED_ALGORITHM* = 156
  EVP_R_UNSUPPORTED_CIPHER* = 107
  EVP_R_UNSUPPORTED_KEYLENGTH* = 123
  EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION* = 124
  EVP_R_UNSUPPORTED_KEY_SIZE* = 108
  EVP_R_UNSUPPORTED_PRF* = 125
  EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM* = 118
  EVP_R_UNSUPPORTED_SALT_TYPE* = 126
  EVP_R_WRONG_FINAL_BLOCK_LENGTH* = 109
  EVP_R_WRONG_PUBLIC_KEY_TYPE* = 110
