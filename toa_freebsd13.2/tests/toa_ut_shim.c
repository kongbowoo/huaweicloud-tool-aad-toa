/* Public-domain strlcpy, identical to the FreeBSD libkern version. */

#include "toa_ut_shim.h"

size_t
strlcpy(char * __restrict dst, const char * __restrict src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';
		while (*src++)
			continue;
	}
	return (src - osrc - 1);
}
