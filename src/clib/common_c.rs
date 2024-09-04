pub const COMMON_C: &str = r#"#include "macros.h"
#include <windows.h>

#define HB {HINT_BYTE}
unsigned char ProKey[] = {{PRO_KEY}};

int strcmpw(_In_ LPCWSTR s1, _In_ LPCWSTR s2) {
    for (; *s1 == *s2; s1++, s2++) {
        if (*s1 == '\0') return 0;
    }

    return ((*(LPCWSTR)s1 < *(LPCWSTR)s2) ? -1 : +1);
}

int strcmpa(_In_ LPCSTR s1, _In_ LPCSTR s2) {
    for (; *s1 == *s2; s1++, s2++) {
        if (*s1 == '\0') return 0;
    }

    return ((*(LPCSTR)s1 < *(LPCSTR)s2) ? -1 : +1);
}
SIZE_T strlena(_In_ LPCSTR s1) {

    LPCSTR s2;

    for (s2 = s1; *s2; ++s2)
        ;

    return (s2 - s1);
}
SIZE_T strlenw(_In_ LPCWSTR s1) {

    LPCWSTR s2;

    for (s2 = s1; *s2; ++s2)
        ;

    return (s2 - s1);
}
void *mini_memcpy(void *dest, void *src, unsigned int len) {
    unsigned int i;
    char *char_src = (char *)src;
    char *char_dest = (char *)dest;
    for (i = 0; i < len; i++) {
        char_dest[i] = char_src[i];
    }
    return dest;
}

void *mini_memset(void *dest, char c, unsigned int len) {
    unsigned int i;
    unsigned int fill;
    unsigned int chunks = len / sizeof(fill);
    char *char_dest = (char *)dest;
    unsigned int *uint_dest = (unsigned int *)dest;

    //
    //  Note we go from the back to the front.  This is to
    //  prevent newer compilers from noticing what we're doing
    //  and trying to invoke the built-in memset instead of us.
    //

    fill = (c << 24) + (c << 16) + (c << 8) + c;

    for (i = len; i > chunks * sizeof(fill); i--) {
        char_dest[i - 1] = c;
    }

    for (i = chunks; i > 0; i--) {
        uint_dest[i - 1] = fill;
    }

    return dest;
}

UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String) {
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = strlena(String);

    while (Index != Length) {
        Hash += String[Index++];
        Hash += Hash << HASH_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String) {
    SIZE_T Index = 0;
    UINT32 Hash = 0;
    SIZE_T Length = strlenw(String);

    while (Index != Length) {
        Hash += String[Index++];
        Hash += Hash << HASH_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}

CHAR UpperChar(CHAR C) {
    if (C >= 'a' && C <= 'z') return C - 'a' + 'A';

    return C;
}

void Xoor(char *buffer, int bufferSize) {
    for (int i = 0, j = 0; i < bufferSize; i++, j++) {
        if (j >= sizeof(ProKey)) j = 0;
        buffer[i] = buffer[i] ^ ProKey[j];
    }
};
void GetKey() {

    BYTE b = 0;

    while (1) {
        if (((ProKey[0] ^ b) - 0) == HB)
            break;
        else
            b++;
    }

    for (int i = 0; i < sizeof(ProKey); i++) {
        ProKey[i] = (BYTE)((ProKey[i] ^ b) ^ i);
    }

    return;
};

"#;
