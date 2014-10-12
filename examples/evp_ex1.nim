import openssl_evp
import strutils
import parseopt2

proc main(name: string) =
  try:
    var ret: cint
    var md_len: cuint
    OpenSSL_add_all_digests()
    let md = EVP_get_digestbyname(name);
    var msg1 = "Test Message"
    var msg2 = "Hello World"
    var md_value: array[EVP_MAX_MD_SIZE, cuchar]
    if (md == nil):
      raise newException(ValueError, "Unknown message digest: " & name)
    let mdctx = EVP_MD_CTX_create()
    # The following functions return 1 on success, 0 on error   
    ret = EVP_DigestInit_ex(mdctx,md,nil)
    if ret != 1:
      raise newException(ValueError, "error calling: EVP_DigestInit_ex")
    ret = EVP_DigestUpdate(mdctx,msg1[0].addr,msg1.len)
    if ret != 1:
      raise newException(ValueError, "error calling: EVP_DigestUpdate for msg1")
    ret = EVP_DigestUpdate(mdctx,msg2[0].addr,msg2.len)
    if ret != 1:
      raise newException(ValueError, "error calling: EVP_DigestUpdate for msg2")
    ret = EVP_DigestFinal_ex(mdctx,md_value[0].addr,md_len.addr)
    if ret != 1:
      raise newException(ValueError, "error calling: EVP_DigestFinal")
    EVP_MD_CTX_destroy(mdctx);
   
    # convert digest to hex string
    var digest = newString(md_len.int * 2)
    for i in 0 .. <md_len.int:
      digest[i*2 .. i*2 +1] = md_value[i].int.toHex(2)
    echo "the digest is: ", digest
    
  except:
    let e = getCurrentException()
    echo e.msg
  finally:
    EVP_cleanup()  
  
proc writeHelp() =
  echo """
Usage: evp_ex1 [DIGEST_NAME]
Hash test strings with [DIGEST_NAME]
DIGEST_NAME should be one of: sha512, sha256, sha1, md5, etc.
"""  

var
  digest = ""
for kind, key, val in getopt():
  case kind
  of cmdArgument:
    digest = key
  of cmdLongOption, cmdShortOption:
    case key
    of "help", "h": 
      writeHelp()
      quit(0)
    else:
      assert(false) # cannot happen   
  of cmdEnd: assert(false) # cannot happen
  
if digest == "":
  writeHelp()
  quit(2)

main(digest)
