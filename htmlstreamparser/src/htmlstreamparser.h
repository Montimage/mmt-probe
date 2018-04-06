/*
 *	HTML stream parser
 *	Copyright (C) 2012 Michael Kowalczyk
 *
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

enum {
	HTML_INNER_TEXT,
	HTML_INNER_TEXT_BEGINNING,
	HTML_TAG,
	HTML_TAG_BEGINNING,
	HTML_TAG_END,
	HTML_NAME,
	HTML_NAME_BEGINNING,
	HTML_NAME_ENDED,
	HTML_ATTRIBUTE,
	HTML_ATTRIBUTE_BEGINNING,
	HTML_ATTRIBUTE_ENDED,
	HTML_VALUE,
	HTML_VALUE_BEGINNING,
	HTML_VALUE_ENDED,
	HTML_VALUE_QUOTED,
	HTML_VALUE_SINGLE_QUOTED,
	HTML_VALUE_DOUBLE_QUOTED,
	HTML_SPACE,
	HTML_EQUALITY,
	HTML_SLASH,
	HTML_CLOSING_TAG,
	HTML_SCRIPT,
	HTML_COMMENT,
	HTML_ENTITY //TODO
};

#define HTML_PART_SIZE 24

typedef struct {
	char parser_state;
	char html_part[HTML_PART_SIZE];
	char *tag_name;
	size_t tag_name_len;
	size_t tag_name_real_len;
	size_t tag_name_max_len;
	char *attr_name;
	size_t attr_name_len;
	size_t attr_name_real_len;
	size_t attr_name_max_len;
	char *attr_value;
	size_t attr_value_len;
	size_t attr_value_real_len;
	size_t attr_value_max_len;
	char *inner_text;
	size_t inner_text_len;
	size_t inner_text_real_len;
	size_t inner_text_max_len;
	char tag_name_to_lower;
	char attr_name_to_lower;
	char attr_val_to_lower;
	char script_equality_len;
} HTMLSTREAMPARSER;

/*
 * Resets the parser to its initial state
 * and release all the buffers.
 */
HTMLSTREAMPARSER *html_parser_reset(HTMLSTREAMPARSER *hsp);

/*
 * Initializes a new parser instance.
 * Returns a pointer to the new instance
 * or NULL if the initialization fails.
 * Run function html_parser_cleanup to
 * deallocate all previsouly allocated memory.
 */
HTMLSTREAMPARSER *html_parser_init();

/*
 * Deallocate all previously allocated memory
 * by the function html_parser_init.
 */
void html_parser_cleanup(HTMLSTREAMPARSER *hsp);

/*
 * Returns 1 if the char specified by the chr argument
 * is the HTML whitespace otherwise returns 0.
 */
inline int ishtmlspace(char chr);

/*
 * Strip HTML whitespace from the end of a string
 * in a place. Returns a reference to the string.
 * Modifies the len argument.
 */
char *html_parser_rtrim(char *src, size_t *len);

/*
 * Strip HTML whitespace from the beginning of a string
 * in a place. Returns a reference to the string.
 * Modifies the len argument.
 */
char *html_parser_ltrim(char *src, size_t *len);

/*
 * Strip HTML whitespace from the beginning and end
 * of a string in a place. Returns a reference to the string.
 * Modifies the len argument.
 */
char *html_parser_trim(char *src, size_t *len);

/*
 * Replace a continuous HTML whitespace strings
 * with the single space char in a place.
 * Returns a reference to the string.
 * Modifies the len argument.
 */
char *html_parser_replace_spaces(char *src, size_t *len);

/*
 * Returns 1 if the parser is inside a part of HTML code
 * specified by the html_part argument otherwise returns 0.
 * Consider that the parser can be in the HTML_TAG
 * or HTML_NAME or HTML_NAME_BEGINNING on the same time.
 */
int html_parser_is_in(HTMLSTREAMPARSER *hsp, int html_part);

/*
 * Parse the char specified by the chr argument.
 * For correct parsing all the HTML code
 * must be passed with correct order.
 */
void html_parser_char_parse(HTMLSTREAMPARSER *hsp, const char c);

/*
 * Setting the argument c to non zero value
 * case changing a tag name char pssed to buffer
 * to lower. Changing this while parsing a tag name
 * affect the buffer from the current position.
 */
void html_parser_set_tag_to_lower(HTMLSTREAMPARSER *hsp, char c);

/*
 * Setting the argument c to non zero value
 * case changing a attribute name char pssed to buffer
 * to lower. Changing this while parsing a attribute name
 * affect the buffer from the current position.
 */
void html_parser_set_attr_to_lower(HTMLSTREAMPARSER *hsp, char c);

/*
 * Setting the argument c to non zero value
 * case changing a attribute value char pssed to buffer
 * to lower. Changing this while parsing a attribute value
 * affect the buffer from the current position.
 */
void html_parser_set_val_to_lower(HTMLSTREAMPARSER *hsp, char c);

/*
 * The argument buffer points to an array
 * to be used as the buffer of current tag name.
 * The argument length is a max array size.
 * The tab name is truncated to the array size.
 */
void html_parser_set_tag_buffer(HTMLSTREAMPARSER *hsp, char *buffer, size_t length);

/*
 * Release a buffer of the tag name.
 * Now the parser always return tag name
 * as null pointer and the length will be 0.
 */
void html_parser_release_tag_buffer(HTMLSTREAMPARSER *hsp);

/*
 * Returns the tag name length
 * not bigger then a buffer size
 * or 0 if still parsing the tag name.
 * A parser set the tag name length to 0
 * at a second tag name beginning.
 */
size_t html_parser_tag_length(HTMLSTREAMPARSER *hsp);

/*
 * Returns the tag name real length
 * can be bigger then a buffer size
 * A parser set the tag name real length to 0
 * at a second tag name beginning.
 */
size_t html_parser_tag_real_length(HTMLSTREAMPARSER *hsp);

/*
 * Returns a reference to the tag name buffer.
 */
char* html_parser_tag(HTMLSTREAMPARSER *hsp);

/*
 * Compares the tag name and the string pointed by p.
 * The argument l is a string length.
 * Returns 1 for equality otherwise returns 0.
 */
int html_parser_cmp_tag(HTMLSTREAMPARSER *hsp, char *p, size_t l);

/*
 * The argument buffer points to an array
 * to be used as the buffer of current attribute name.
 * The argument length is a max array size.
 * The attribute name is truncated to the array size.
 */
void html_parser_set_attr_buffer(HTMLSTREAMPARSER *hsp, char *buffer, size_t length);

/*
 * Release a buffer of the attribute name.
 * Now the parser always return attribute name
 * as null pointer and the length will be 0.
 */
void html_parser_release_attr_buffer(HTMLSTREAMPARSER *hsp);

/*
 * Returns the attribute name length
 * not bigger then a buffer size
 * or 0 if still parsing the attribute name.
 * A parser set the attribute name length to 0
 * at a second attribute name beginning
 * or a tag name beggining.
 */
size_t html_parser_attr_length(HTMLSTREAMPARSER *hsp);

/*
 * Returns the attribute name real length
 * can be bigger then a buffer size
 * A parser set the attribute name real length to 0
 * at a second attribute name beginning
 * or a tag name beggining.
 */
size_t html_parser_attr_real_length(HTMLSTREAMPARSER *hsp);

/*
 * Returns a reference to the attribute name buffer.
 */
char* html_parser_attr(HTMLSTREAMPARSER *hsp);

/*
 * Compares the attribute name and the string pointed by p.
 * The argument l is a string length.
 * Returns 1 for equality otherwise returns 0.
 */
int html_parser_cmp_attr(HTMLSTREAMPARSER *hsp, char *p, size_t l);

/*
 * The argument buffer points to an array
 * to be used as the buffer of current attribute value.
 * The argument length is a max array size.
 * The attribute value is truncated to the array size.
 */
void html_parser_set_val_buffer(HTMLSTREAMPARSER *hsp, char *buffer, size_t length);

/*
 * Release a buffer of the attribute value.
 * Now the parser always return attribute value
 * as null pointer and the length will be 0.
 */
void html_parser_release_val_buffer(HTMLSTREAMPARSER *hsp);

/*
 * Returns the attribute value length
 * not bigger then a buffer size
 * or 0 if still parsing the attribute value.
 * A parser set the attribute value length to 0
 * at a second attribute value beginning
 * or a attribute name beginning
 * or a tag name beggining.
 */
size_t html_parser_val_length(HTMLSTREAMPARSER *hsp);

/*
 * Returns the attribute value real length
 * can be bigger then a buffer size
 * A parser set the attribute value real length to 0
 * at a second attribute value beginning
 * or a attribute name beginning
 * or a tag name beggining.
 */
size_t html_parser_val_real_length(HTMLSTREAMPARSER *hsp);

/*
 * Returns a reference to the attribute value buffer.
 */
char* html_parser_val(HTMLSTREAMPARSER *hsp);

/*
 * Compares the attribute value and the string pointed by p.
 * The argument l is a string length.
 * Returns 1 for equality otherwise returns 0.
 */
int html_parser_cmp_val(HTMLSTREAMPARSER *hsp, char *p, size_t l);

/*
 * The argument buffer points to an array
 * to be used as the buffer of current inner text.
 * The argument length is a max array size.
 * The inner text is truncated to the array size.
 */
void html_parser_set_inner_text_buffer(HTMLSTREAMPARSER *hsp, char *buffer, size_t length);

/*
 * Release a buffer of the inner text.
 * Now the parser always return inner text
 * as null pointer and the length will be 0.
 */
void html_parser_release_inner_text_buffer(HTMLSTREAMPARSER *hsp);

/*
 * Returns the inner text length
 * not bigger then a buffer size
 * or 0 if still parsing the inner text.
 * A parser set the inner text length to 0
 * at a second inner text beginning.
 */
size_t html_parser_inner_text_length(HTMLSTREAMPARSER *hsp);

/*
 * Returns the inner text real length
 * can be bigger then a buffer size
 * A parser set the inner text real length to 0
 * at a second inner text beginning.
 */
size_t html_parser_inner_text_real_length(HTMLSTREAMPARSER *hsp);

/*
 * Returns a reference to the inner text buffer.
 */
char* html_parser_inner_text(HTMLSTREAMPARSER *hsp);

/*
 * Compares the innet text and the string pointed by p.
 * The argument l is a string length.
 * Returns 1 for equality otherwise returns 0.
 */
int html_parser_cmp_inner_text(HTMLSTREAMPARSER *hsp, char *p, size_t l);

