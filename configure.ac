AC_INIT([nim_openssl_evp], [0.1], [test@example.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CHECK_HEADERS([string.h openssl/evp.h])
PKG_CHECK_MODULES(OPENSSL, openssl)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 examples/Makefile
])
AC_OUTPUT
