/*
 * Copyright © 2026 Håvard Sørbø
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>

#include "check.h"
#include "plist.h"

static const char events[]
		= "<dict>\n"
		  "\t<key>com.apple.duetexpertd.promptexecutionmerging</key>"
		  " <!--Unique Activity name-->\n"
		  "\t<dict>\n"
		  "\t\t<key>Priority</key>\n"
		  "\t\t<string>Utility</string> <!--Supports \"<dict>\"-->\n"
		  "\t\t<key>RepeatingTask</key> <!--Mandatory Timing "
		  "Dictionary-->\n"
		  "\t\t<dict>\n"
		  "\t\t\t<key>Interval</key> <!--Mandatory-->\n"
		  "\t\t\t<integer>86400</integer>\n"
		  "\t\t</dict>\n"
		  "\t</dict>\n"
		  "\t<key>next</key>\n"
		  "\t<dict/>\n"
		  "</dict>\n";

int
main(void)
{
	const char *end = events + strlen(events);

	const char *key = strstr(events, "</key>") + 6;
	const char *value = plist_skip(key, end);
	CHECK(strncmp(value, "<dict>\n\t\t<key>Priority", 22) == 0);
	CHECK(plist_skip(end, end) == end);
	const char *unclosed = "  <!-- no end";
	CHECK(plist_skip(unclosed, unclosed + strlen(unclosed))
			== unclosed + strlen(unclosed));

	const char *value_end = plist_value_end(value, end);
	CHECK(strncmp(plist_skip(value_end, end), "<key>next</key>", 15) == 0);

	const char *dictionary_end;
	const char *timing = plist_dictionary(
			events, end, "RepeatingTask", &dictionary_end);
	CHECK(timing != NULL);
	CHECK(strncmp(plist_skip(dictionary_end, end), "</dict>", 7) == 0);
	char priority[32];
	CHECK(plist_string(value, value_end, "Priority", priority,
			sizeof(priority)));
	CHECK(strcmp(priority, "Utility") == 0);
	return 0;
}
