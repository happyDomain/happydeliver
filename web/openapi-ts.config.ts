import { defineConfig } from "@hey-api/openapi-ts";

export default defineConfig({
    input: "../api/openapi.yaml",
    output: "src/lib/api",
    plugins: [
        {
            name: "@hey-api/client-fetch",
            runtimeConfigPath: "./src/lib/hey-api.ts",
        },
    ],
});
