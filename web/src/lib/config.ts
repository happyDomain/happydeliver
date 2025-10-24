// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
// Authors: Pierre-Olivier Mercier, et al.
//
// This program is offered under a commercial and under the AGPL license.
// For commercial licensing, contact us at <contact@happydomain.org>.
//
// For AGPL licensing:
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { writable } from "svelte/store";

interface AppConfig {
    report_retention?: number;
}

const defaultConfig: AppConfig = {
    report_retention: 0,
};

function getConfigFromScriptTag(): AppConfig | null {
    if (typeof document !== "undefined") {
        const configScript = document.getElementById("app-config");
        if (configScript) {
            try {
                return JSON.parse(configScript.textContent || "");
            } catch (e) {
                console.error("Failed to parse app config:", e);
            }
        }
    }
    return null;
}

const initialConfig = getConfigFromScriptTag() || defaultConfig;

export const appConfig = writable<AppConfig>(initialConfig);
