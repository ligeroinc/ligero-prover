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

#include <ligetron/api.h>

int minDistance(const char* word1, const char* word2, int m, int n) {
    int pre;
    int cur[n + 1];

    for (int j = 0; j <= n; j++) {
        cur[j] = j;
    }
    
    for (int i = 1; i <= m; i++) {
        pre = cur[0];
        cur[0] = i;
        for (int j = 1; j <= n; j++) {
            int temp = cur[j];
            bool cond = word1[i - 1] == word2[j - 1];
            cur[j] = oblivious_if(cond,
                                  pre,
                                  oblivious_min(pre, oblivious_min(cur[j - 1], cur[j])) + 1);
            pre = temp;
        }
    }
    return cur[n];
}
