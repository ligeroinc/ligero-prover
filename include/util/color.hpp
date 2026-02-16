/*
 * Copyright (C) 2023-2026 Ligero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#if defined(__EMSCRIPTEN__)
#define ANSI_RESET       ""
#define ANSI_BLACK       ""
#define ANSI_RED         ""
#define ANSI_GREEN       ""
#define ANSI_YELLOW      ""
#define ANSI_BLUE        ""
#define ANSI_MAGENTA     ""
#define ANSI_CYAN        ""
#define ANSI_WHITE       ""
#define ANSI_BOLDBLACK   ""
#define ANSI_BOLDRED     ""
#define ANSI_BOLDGREEN   ""
#define ANSI_BOLDYELLOW  ""
#define ANSI_BOLDBLUE    ""
#define ANSI_BOLDMAGENTA ""
#define ANSI_BOLDCYAN    ""
#define ANSI_BOLDWHITE   ""

#else
//the following are UBUNTU/LINUX, and MacOS ONLY terminal color codes.
#define ANSI_RESET   "\033[0m"
#define ANSI_BLACK   "\033[30m"      /* Black */
#define ANSI_RED     "\033[31m"      /* Red */
#define ANSI_GREEN   "\033[32m"      /* Green */
#define ANSI_YELLOW  "\033[33m"      /* Yellow */
#define ANSI_BLUE    "\033[34m"      /* Blue */
#define ANSI_MAGENTA "\033[35m"      /* Magenta */
#define ANSI_CYAN    "\033[36m"      /* Cyan */
#define ANSI_WHITE   "\033[37m"      /* White */
#define ANSI_BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define ANSI_BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define ANSI_BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define ANSI_BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define ANSI_BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define ANSI_BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define ANSI_BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define ANSI_BOLDWHITE   "\033[1m\033[37m"      /* Bold White */
#endif
