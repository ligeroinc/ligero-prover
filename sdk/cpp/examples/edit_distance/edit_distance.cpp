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

#include "edit_distance.h"

/************************************************************
 * Arguments:
 *     [1]: <str> Input text A
 *     [2]: <str> Input text B
 *     [3]: <i64> Length of input text A
 *     [4]: <i64> Length of input text B
 ************************************************************/

int main(int argc, char *argv[]) {
    int dist = minDistance(argv[1],
                           argv[2],
                           *reinterpret_cast<const int*>(argv[3]),
                           *reinterpret_cast<const int*>(argv[4]));
    
    assert_one(dist < 5);
    return 0;
}
