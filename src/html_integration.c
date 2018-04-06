#include "html_integration.h"
#include <assert.h>

#ifdef HTTP_RECONSTRUCT

/**
 * Sends a data chunk for processing by the html parser.
 * In this case, extract "href" attribute from "a" tags.
 */
void html_parse(const char * chunck, size_t len, html_parser_t * hp, http_content_processor_t * sp) {
  HTMLSTREAMPARSER * hsp = hp->hsp;

  // Parse HTML data byte by byte
  size_t i;
  for (i = 0; i < len; i++) {
    html_parser_char_parse(hsp, ((char *)chunck)[i]);
    if (html_parser_cmp_tag(hsp, "a", 1))
      if (html_parser_cmp_attr(hsp, "href", 4))
        if (html_parser_is_in(hsp, HTML_VALUE_ENDED)) {
          html_parser_val(hsp)[html_parser_val_length(hsp)] = '\0';
          // printf("html_parse -]> %s\n", html_parser_val(hsp));
        }
  }
  return;
}

/* report a zlib or i/o error */
void zerr(int ret)
{
    fputs("[error] zpipe: ", stderr);
    switch (ret) {
    case Z_ERRNO:
        if (ferror(stdin))
            fputs("reading stdin\n", stderr);
        if (ferror(stdout))
            fputs("writing stdout\n", stderr);
        break;
    case Z_STREAM_ERROR:
        fputs("invalid compression level\n", stderr);
        break;
    case Z_DATA_ERROR:
        fputs("invalid or incomplete deflate data\n", stderr);
        break;
    case Z_MEM_ERROR:
        fputs("out of memory\n", stderr);
        break;
    case Z_VERSION_ERROR:
        fputs("zlib version mismatch!\n", stderr);
    }
}

/* Decompress from @chunk @gzp output until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
void gzip_process(const char * chunck, size_t len, gzip_processor_t * gzp, http_content_processor_t * sp ,char *filename)
{

  gzp->strm.avail_in = len;
  if (gzp->strm.avail_in == 0) {
    fprintf(stderr, "[error] Processing empty gzip chunk! check why the hell we got here\n");
    return;
  }

  gzp->strm.next_in = (z_const Bytef *)chunck;

  /* run inflate() on input until output buffer not full */
  do {
    unsigned have;
    gzp->strm.avail_out = CHUNK;
    gzp->strm.next_out = gzp->out;
    gzp->ret = inflate(& gzp->strm, Z_NO_FLUSH);
    assert(gzp->ret != Z_STREAM_ERROR);  /* state not clobbered */
    switch (gzp->ret) {
      case Z_NEED_DICT:
        gzp->ret = Z_DATA_ERROR;     /* and fall through */
      case Z_DATA_ERROR:
      case Z_MEM_ERROR:
        zerr(gzp->ret);
        sp->pre_processor = clean_gzip_processor( gzp );
        // fprintf(stderr, "[error] gzip_process: There is some error!\n");
        return;
    }
    // This is how much we have deconmpressed
    have = CHUNK - gzp->strm.avail_out;

    // Process decompressed data to html parser if any
    if( sp->content_type && sp->processor ) {
      html_parser_t * hp = (html_parser_t *) sp->processor;
      // printf("gzip_process gzp->out: %s\n", gzp->out);
      if(filename!=NULL){
        // printf("gzip_process: writing data to file: %s\n",filename);
        http_write_data_to_file(filename,(const char*)gzp->out,strlen((const char*)gzp->out));  
      }else{
        fprintf(stderr, "[error] gzip_process: filename is NULL\n");
      }
      html_parse((const char*)gzp->out, have, hp, sp);
    }
  } while (gzp->strm.avail_out == 0); //continue while we still have data to decompress
}

#endif // End of HTTP_RECONSTRUCT
