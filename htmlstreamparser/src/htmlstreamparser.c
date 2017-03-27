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

#include <stdio.h>
#include <htmlstreamparser.h>

HTMLSTREAMPARSER *html_parser_reset(HTMLSTREAMPARSER *hsp) {
	memset(hsp->html_part, 0, HTML_PART_SIZE);
	hsp->parser_state = 0;
	hsp->tag_name_max_len = 0;
	hsp->attr_name_max_len = 0;
	hsp->attr_value_max_len = 0;
	hsp->inner_text_max_len = 0;
	hsp->tag_name_len = 0;
	hsp->attr_name_len = 0;
	hsp->attr_value_len = 0;
	hsp->inner_text_len = 0;
	hsp->tag_name_real_len = 0;
	hsp->attr_name_real_len = 0;
	hsp->attr_value_real_len = 0;
	hsp->inner_text_real_len = 0;
	hsp->tag_name = NULL;
	hsp->attr_name = NULL;
	hsp->attr_value = NULL;
	hsp->inner_text = NULL;
	hsp->tag_name_to_lower = 0;
	hsp->attr_name_to_lower = 0;
	hsp->attr_val_to_lower = 0;
	hsp->script_equality_len = 0;
	return hsp;
}

HTMLSTREAMPARSER *html_parser_init() { return html_parser_reset((HTMLSTREAMPARSER *) malloc(sizeof(HTMLSTREAMPARSER))); }

void html_parser_cleanup(HTMLSTREAMPARSER *hsp) { free(hsp); }

inline int ishtmlspace(char chr) { return ((chr == ' ' || chr == '\t' || chr == '\n' || chr == '\r')); }

char *html_parser_rtrim(char *src, size_t *len) { while (ishtmlspace(src[(*len)-1]) && *len > 0) { (*len)--; } return src; }

char *html_parser_ltrim(char *src, size_t *len) { while (ishtmlspace(*src) && *len > 0) { src++; (*len)--; } return src; }

char *html_parser_trim(char *src, size_t *len) { return html_parser_rtrim(html_parser_ltrim(src, len), len); }

char *html_parser_replace_spaces(char *src, size_t *len) {
	char ws = 1;
	size_t i = 0, l = 0;
	while (i < *len) {
		if (!ishtmlspace(src[i])) {
			src[l++] = src[i];
			ws = 1;
		} else if (ws) {
			src[l++] = ' ';
			ws = 0;
		}
		i++;
	}
	*len = l;
	return src;
}

int html_parser_is_in(HTMLSTREAMPARSER *hsp, int html_part) { if (html_part >= 0 && html_part < HTML_PART_SIZE) return hsp->html_part[html_part]; else return 0; }

void html_parser_char_parse(HTMLSTREAMPARSER *hsp, const char c) {
	char *s = &hsp->parser_state, *h = hsp->html_part, *l = &hsp->script_equality_len;
	const char script[] = "script";
	if (*s == 0 && *l == 6) { *s = 10; memset(h, 0, HTML_PART_SIZE); h[HTML_SCRIPT] = 1; }
	switch (*s) {
		case 0: // inside the inner text
			if (c == '<') { *s = 1; memset(h, 0, HTML_PART_SIZE); h[HTML_TAG] = 1; h[HTML_TAG_BEGINNING] = 1; }
			else {
				if (!h[HTML_INNER_TEXT]) {
					memset(h, 0, HTML_PART_SIZE); h[HTML_INNER_TEXT] = 1; h[HTML_INNER_TEXT_BEGINNING] = 1;
				} else h[HTML_INNER_TEXT_BEGINNING] = 0;
			}
			break;
		case 1: // tag beginning
			h[HTML_TAG_BEGINNING] = 0;
			*l = 0;
			if (c == '/') { *s = 2; h[HTML_CLOSING_TAG] = 1; h[HTML_SLASH] = 1; h[HTML_NAME] = 1; h[HTML_NAME_BEGINNING] = 1; }
			else if (c == '!') { *s = 9; h[HTML_COMMENT] = 1; }
			else if (c == '>') { *s = 0; h[HTML_TAG_END] = 1; }
			else if (isalpha(c)) { *s = 2; h[HTML_NAME] = 1; h[HTML_NAME_BEGINNING] = 1; }
			else if (c != '<') { *s = 0; memset(h, 0, HTML_PART_SIZE); h[HTML_INNER_TEXT] = 1; h[HTML_INNER_TEXT_BEGINNING] = 1; }
			break;
		case 2: // inside a tag name
			h[HTML_NAME_BEGINNING] = 0;
			h[HTML_SLASH] = 0;
			if (c == '>') { *s = 0; h[HTML_TAG_END] = 1; h[HTML_NAME_ENDED] = 1; h[HTML_NAME] = 0; }
			else if (ishtmlspace(c)) { *s = 3; h[HTML_SPACE] = 1; h[HTML_NAME_ENDED] = 1; h[HTML_NAME] = 0; }
			break;
		case 3: // tag space
			h[HTML_NAME_ENDED] = 0;
			h[HTML_ATTRIBUTE_ENDED] = 0;
			h[HTML_VALUE_ENDED] = 0;
			h[HTML_VALUE_QUOTED] = 0;
			h[HTML_VALUE_SINGLE_QUOTED] = 0;
			h[HTML_VALUE_DOUBLE_QUOTED] = 0;
			h[HTML_EQUALITY] = 0;
			if (!ishtmlspace(c)) {
				h[HTML_SPACE] = 0;
				if (c == '>') { *s = 0; h[HTML_TAG_END] = 1; }
				else if (c == '=') { *s = 5; h[HTML_EQUALITY] = 1; }
				else { *s = 4; h[HTML_ATTRIBUTE] = 1; h[HTML_ATTRIBUTE_BEGINNING] = 1; }
			}
			break;
		case 4: // inside an attribute name
			h[HTML_ATTRIBUTE_BEGINNING] = 0;
			if (c == '>') { *s = 0; h[HTML_TAG_END] = 1; h[HTML_ATTRIBUTE] = 0; h[HTML_ATTRIBUTE_ENDED] = 1; }
			else if (c == '=') { *s = 5; h[HTML_EQUALITY] = 1; h[HTML_ATTRIBUTE] = 0; h[HTML_ATTRIBUTE_ENDED] = 1; }
			else if (ishtmlspace(c)) { *s = 3; h[HTML_SPACE] = 1; h[HTML_ATTRIBUTE] = 0; h[HTML_ATTRIBUTE_ENDED] = 1; }
			break;
		case 5: // before an attribute value
			h[HTML_EQUALITY] = 0;
			h[HTML_ATTRIBUTE_ENDED] = 0;
			h[HTML_SPACE] = 1;
			if (!ishtmlspace(c)) {
				h[HTML_SPACE] = 0;
				if (c == '>') { *s = 0; h[HTML_TAG_END] = 1; }
				else if (c == '"') { *s = 6; h[HTML_VALUE_QUOTED] = 1; h[HTML_VALUE_DOUBLE_QUOTED] = 1; }
				else if (c == '\'') { *s = 7; h[HTML_VALUE_QUOTED] = 1; h[HTML_VALUE_SINGLE_QUOTED] = 1; }
				else { *s = 8; h[HTML_VALUE] = 1; h[HTML_VALUE_BEGINNING] = 1; }
			}
			break;
		case 6: // inside an attribute value and the value is surrounded by double quotes
			if (!h[HTML_VALUE]) { h[HTML_VALUE] = 1; h[HTML_VALUE_BEGINNING] = 1; }
			else h[HTML_VALUE_BEGINNING] = 0;
			if (c == '"') { *s = 3; h[HTML_VALUE] = 0; h[HTML_VALUE_ENDED] = 1; }
			break;
		case 7: // inside an attribute value and the value is surrounded by single quotes
			h[HTML_VALUE] = 1; h[HTML_VALUE_BEGINNING] = 0;
			if (c == '\'') { *s = 3; h[HTML_VALUE] = 0; h[HTML_VALUE_ENDED] = 1; }
			break;
		case 8: // inside an attribute value and the value is not surrounded by single or double quotes
			h[HTML_VALUE_BEGINNING] = 0;
			if (c == '>') { *s = 0; h[HTML_TAG_END] = 1; h[HTML_VALUE] = 0; h[HTML_VALUE_ENDED] = 1; }
			else if (ishtmlspace(c)) { *s = 3; h[HTML_SPACE] = 1; h[HTML_VALUE] = 0; h[HTML_VALUE_ENDED] = 1; }
			break;
		case 9: // inside a comment
			if (c == '>') { *s = 0; h[HTML_TAG_END] = 1; }
			break;
		case 10: // searching script end
			if (c == '<') *s = 11;
			break;
		case 11:
			if (c != '<') {
				if (c == '/') {
					*s = 12; *l = 0;
				} else *s = 10;
			}
			break;
		case 12:
		case 13:
			if (c == '<') *s = 11;
			else if (c == '>' && *l == 6) { *s = 0; *l = 0; h[HTML_SCRIPT] = 0; h[HTML_TAG] = 1; h[HTML_TAG_END] = 1; h[HTML_NAME_ENDED] = 1; h[HTML_CLOSING_TAG] = 1; }
			else if (ishtmlspace(c) && *l == 6) { *s = 3; *l = 0; h[HTML_SCRIPT] = 0; h[HTML_TAG] = 1; h[HTML_SPACE] = 1; h[HTML_NAME_ENDED] = 1; h[HTML_CLOSING_TAG] = 1; }
			else *s = 13;
			break;
	}
	if (*s == 2 || *s == 13) if (*l >= 0 && *l < 6) if (script[*l] == tolower(c)) (*l)++; else *l = -1; else *l = -1;

	if (h[HTML_INNER_TEXT]) {
		if (h[HTML_INNER_TEXT_BEGINNING]) { hsp->inner_text_len = 0; hsp->inner_text_real_len = 0; }
		if (hsp->inner_text_len < hsp->inner_text_max_len) hsp->inner_text[hsp->inner_text_len++] = c;
		hsp->inner_text_real_len++;
	} else if (h[HTML_NAME] || *s == 12 || *s == 13) {
		if (h[HTML_NAME_BEGINNING] || *s == 12) {
			hsp->tag_name_len = 0; hsp->attr_name_len = 0; hsp->attr_value_len = 0;
			hsp->tag_name_real_len = 0; hsp->attr_name_real_len = 0; hsp->attr_value_real_len = 0;
		}
		if (hsp->tag_name_len < hsp->tag_name_max_len)
			if (hsp->tag_name_to_lower) hsp->tag_name[hsp->tag_name_len++] = tolower(c);
			else hsp->tag_name[hsp->tag_name_len++] = c;
		hsp->tag_name_real_len++;
	} else if (h[HTML_ATTRIBUTE]) {
		if (h[HTML_ATTRIBUTE_BEGINNING]) {
			hsp->attr_name_len = 0; hsp->attr_value_len = 0;
			hsp->attr_name_real_len = 0; hsp->attr_value_real_len = 0;
		}
		if (hsp->attr_name_len < hsp->attr_name_max_len)
			if (hsp->attr_name_to_lower) hsp->attr_name[hsp->attr_name_len++] = tolower(c);
			else hsp->attr_name[hsp->attr_name_len++] = c;
		hsp->attr_name_real_len++;
	} else if (h[HTML_VALUE]) {
		if (h[HTML_VALUE_BEGINNING]) { hsp->attr_value_len = 0; hsp->attr_value_real_len = 0; }
		if (hsp->attr_value_len < hsp->attr_value_max_len)
			if (hsp->attr_val_to_lower) hsp->attr_value[hsp->attr_value_len++] = tolower(c);
			else hsp->attr_value[hsp->attr_value_len++] = c;
		hsp->attr_value_real_len++;
	}
}

void html_parser_set_tag_to_lower(HTMLSTREAMPARSER *hsp, char c) { hsp->tag_name_to_lower = c; }

void html_parser_set_attr_to_lower(HTMLSTREAMPARSER *hsp, char c) { hsp->attr_name_to_lower = c; }

void html_parser_set_val_to_lower(HTMLSTREAMPARSER *hsp, char c) { hsp->attr_val_to_lower = c; }


void html_parser_set_tag_buffer(HTMLSTREAMPARSER *hsp, char *buffer, size_t length) { hsp->tag_name = buffer; hsp->tag_name_max_len = length; }

void html_parser_release_tag_buffer(HTMLSTREAMPARSER *hsp) { hsp->tag_name = NULL; hsp->tag_name_len = 0; hsp->tag_name_max_len = 0; }

size_t html_parser_tag_length(HTMLSTREAMPARSER *hsp) { if (!hsp->html_part[HTML_NAME] && hsp->parser_state != 12 && hsp->parser_state != 13) return hsp->tag_name_len; else return 0; }

size_t html_parser_tag_real_length(HTMLSTREAMPARSER *hsp) { return hsp->tag_name_real_len; }

char* html_parser_tag(HTMLSTREAMPARSER *hsp) { return hsp->tag_name; }

int html_parser_cmp_tag(HTMLSTREAMPARSER *hsp, char *p, size_t l) { if (html_parser_tag_length(hsp) == l) if (strncmp(p, hsp->tag_name, l) == 0) return 1; return 0; }


void html_parser_set_attr_buffer(HTMLSTREAMPARSER *hsp, char *buffer, size_t length) { hsp->attr_name = buffer; hsp->attr_name_max_len = length; }

void html_parser_release_attr_buffer(HTMLSTREAMPARSER *hsp) { hsp->attr_name = NULL; hsp->attr_name_len = 0; hsp->attr_name_max_len = 0; }

size_t html_parser_attr_length(HTMLSTREAMPARSER *hsp) { if (!hsp->html_part[HTML_ATTRIBUTE]) return hsp->attr_name_len; else return 0; }

size_t html_parser_attr_real_length(HTMLSTREAMPARSER *hsp) { return hsp->attr_name_real_len; }

char* html_parser_attr(HTMLSTREAMPARSER *hsp) { return hsp->attr_name; }

int html_parser_cmp_attr(HTMLSTREAMPARSER *hsp, char *p, size_t l) { if (html_parser_attr_length(hsp) == l) if (strncmp(p, hsp->attr_name, l) == 0) return 1; return 0; }


void html_parser_set_val_buffer(HTMLSTREAMPARSER *hsp, char *buffer, size_t length) { hsp->attr_value = buffer; hsp->attr_value_max_len = length; }

void html_parser_release_val_buffer(HTMLSTREAMPARSER *hsp) { hsp->attr_value = NULL; hsp->attr_value_len = 0; hsp->attr_value_max_len = 0; }

size_t html_parser_val_length(HTMLSTREAMPARSER *hsp) { if (!hsp->html_part[HTML_VALUE]) return hsp->attr_value_len; else return 0; }

size_t html_parser_val_real_length(HTMLSTREAMPARSER *hsp) { return hsp->attr_value_real_len; }

char* html_parser_val(HTMLSTREAMPARSER *hsp) { return hsp->attr_value; }

int html_parser_cmp_val(HTMLSTREAMPARSER *hsp, char *p, size_t l) { if (html_parser_val_length(hsp) == l) if (strncmp(p, hsp->attr_value, l) == 0) return 1; return 0; }


void html_parser_set_inner_text_buffer(HTMLSTREAMPARSER *hsp, char *buffer, size_t length) { hsp->inner_text = buffer; hsp->inner_text_max_len = length; }

void html_parser_release_inner_text_buffer(HTMLSTREAMPARSER *hsp) { hsp->inner_text = NULL; hsp->inner_text_len = 0; hsp->inner_text_max_len = 0; }

size_t html_parser_inner_text_length(HTMLSTREAMPARSER *hsp) { if (!hsp->html_part[HTML_INNER_TEXT]) return hsp->inner_text_len; else return 0; }

size_t html_parser_inner_text_real_length(HTMLSTREAMPARSER *hsp) { return hsp->inner_text_real_len; }

char* html_parser_inner_text(HTMLSTREAMPARSER *hsp) { return hsp->inner_text; }

int html_parser_cmp_inner_text(HTMLSTREAMPARSER *hsp, char *p, size_t l) { if (html_parser_inner_text_length(hsp) == l) if (strncmp(p, hsp->inner_text, l) == 0) return 1; return 0; }


