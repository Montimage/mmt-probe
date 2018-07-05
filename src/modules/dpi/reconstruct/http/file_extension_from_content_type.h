/* Generated on Wed Jul  4 17:09:32 CEST 2018 */
/* ANSI-C code produced by gperf version 3.0.4 */
/* Command-line: gperf src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf  */
/* Computed positions: -k'7,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif

#line 1 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"

#line 14 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
struct file_extension{
   const char* content_type;
   const char* file_extension;
};
#include <string.h>
/* maximum key range = 77, duplicates = 0 */

#ifndef GPERF_DOWNCASE
#define GPERF_DOWNCASE 1
static unsigned char gperf_downcase[256] =
  {
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
     30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
     45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
     60,  61,  62,  63,  64,  97,  98,  99, 100, 101, 102, 103, 104, 105, 106,
    107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122,  91,  92,  93,  94,  95,  96,  97,  98,  99, 100, 101, 102, 103, 104,
    105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
    165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255
  };
#endif

#ifndef GPERF_CASE_STRNCMP
#define GPERF_CASE_STRNCMP 1
static int
gperf_case_strncmp (register const char *s1, register const char *s2, register unsigned int n)
{
  for (; n > 0;)
    {
      unsigned char c1 = gperf_downcase[(unsigned char)*s1++];
      unsigned char c2 = gperf_downcase[(unsigned char)*s2++];
      if (c1 != 0 && c1 == c2)
        {
          n--;
          continue;
        }
      return (int)c1 - (int)c2;
    }
  return 0;
}
#endif

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
get_content_type_hash (register const char *str, register unsigned int len)
{
  static const unsigned char asso_values[] =
    {
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80,  0, 80, 35, 80, 80,
       5,  0, 35, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80,  0, 80, 80, 20,  0,
       0,  5, 45, 80, 30,  5,  0, 25, 25,  0,
      45, 80, 80, 30, 15, 80,  5, 80, 15,  0,
      80, 80, 80, 80, 80, 80, 80,  0, 80, 80,
      20,  0,  0,  5, 45, 80, 30,  5,  0, 25,
      25,  0, 45, 80, 80, 30, 15, 80,  5, 80,
      15,  0, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
      80, 80, 80, 80, 80, 80
    };
  register int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[6]];
      /*FALLTHROUGH*/
      case 6:
      case 5:
      case 4:
      case 3:
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

#ifdef __GNUC__
__inline
#if defined __GNUC_STDC_INLINE__ || defined __GNUC_GNU_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
const struct file_extension *
get_file_extension_from_content_type (register const char *str, register unsigned int len)
{
  enum
    {
      TOTAL_KEYWORDS = 45,
      MIN_WORD_LENGTH = 3,
      MAX_WORD_LENGTH = 42,
      MIN_HASH_VALUE = 3,
      MAX_HASH_VALUE = 79
    };

  static const struct file_extension wordlist[] =
    {
      {""}, {""}, {""},
#line 45 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"mp3",                           "mp3"},
      {""}, {""}, {""}, {""}, {""},
#line 44 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"font/woff",                     "woff"},
      {""}, {""}, {""}, {""},
#line 37 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"image/gif",                     "gif"},
#line 24 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/xml",               "xml"},
      {""},
#line 55 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-amf",             "amf"},
#line 42 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-woff",            "woff"},
#line 25 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/rss+xml",           "xml"},
#line 26 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/atom+xml",          "xml"},
#line 20 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/xhtml+xml",         "html"},
#line 40 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-font-ttf",        "tff"},
#line 41 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-font-woff",       "woff"},
#line 19 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"text/html",                     "html"},
#line 56 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/ocsp-response",     "ocsp"},
#line 22 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"text/x-cross-domain-policy",    "txt"},
#line 43 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/font-woff2",        "woff"},
#line 57 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-debian-package",  "deb"},
#line 51 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"video/x-ms-asf",                "asf"},
#line 30 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"text/javascript",               "js"},
#line 50 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"video/x-flv",                   "flv"},
      {""},
#line 23 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"text/xml",                      "xml"},
#line 59 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-unknown-content-type",         "dat"},
#line 21 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"text/plain",                    "txt"},
      {""},
#line 32 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/javascript",        "js"},
#line 47 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"mp4",                           "mp4"},
#line 31 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-javascript",      "js"},
      {""},
#line 29 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/json",              "json"},
#line 63 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/vnd.google.safebrowsing-update", "dat"},
#line 33 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"image/svg+xml",                 "svg"},
#line 35 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"image/jpg",                     "jpg"},
#line 36 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"image/jpeg",                    "jpg"},
#line 62 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/vnd.google.safebrowsing-chunk",  "dat"},
#line 54 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-fcs",             "fcs"},
#line 52 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"zip",                           "zip"},
#line 61 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/octet-stream",                   "dat"},
#line 49 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"video/MP2T",                    "mp4"},
      {""},
#line 38 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"image/x-icon",                  "icon"},
#line 60 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-www-form-urlencoded",          "dat"},
#line 39 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"image/vnd.microsoft.icon",      "icon"},
      {""}, {""}, {""}, {""},
#line 34 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"image/png",                     "png"},
#line 53 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/zip",               "zip"},
      {""}, {""}, {""},
#line 28 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"text/json",                     "json"},
      {""}, {""}, {""},
#line 27 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"text/css",                      "css"},
#line 48 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"audio/mp4",                     "mp4"},
      {""}, {""}, {""}, {""},
#line 46 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"application/x-shockwave-flash", "swf"},
      {""}, {""}, {""}, {""},
#line 58 "src/modules/dpi/reconstruct/http/file_extension_from_content_type.gperf"
      {"binary/octet-stream",                        "dat"}
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = get_content_type_hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key].content_type;

          if ((((unsigned char)*str ^ (unsigned char)*s) & ~32) == 0 && !gperf_case_strncmp (str, s, len) && s[len] == '\0')
            return &wordlist[key];
        }
    }
  return 0;
}
