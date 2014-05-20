
#include <idsa.h>

#ifdef VERSION
static char *idsa_version_string = VERSION;
#else
static char *idsa_version_string = "unknown";
#endif

char *idsa_version_runtime()
{
  return idsa_version_string;
}
