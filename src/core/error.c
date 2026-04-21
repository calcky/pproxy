/* core/error.c -- 错误码字符串 */
#include "pproxy/pproxy.h"

const char *pp_strerror(int err)
{
    switch (err) {
    case PP_OK:            return "ok";
    case PP_ERR_GENERIC:   return "generic error";
    case PP_ERR_NOMEM:     return "out of memory";
    case PP_ERR_INVAL:     return "invalid argument";
    case PP_ERR_AGAIN:     return "try again";
    case PP_ERR_NOTFOUND:  return "not found";
    case PP_ERR_EXIST:     return "already exists";
    case PP_ERR_FULL:      return "queue full";
    case PP_ERR_EMPTY:     return "queue empty";
    case PP_ERR_CLOSED:    return "closed";
    case PP_ERR_TIMEOUT:   return "timeout";
    case PP_ERR_IO:        return "i/o error";
    case PP_ERR_PROTO:     return "protocol error";
    case PP_ERR_NOSUPPORT: return "not supported";
    default:               return "unknown error";
    }
}
