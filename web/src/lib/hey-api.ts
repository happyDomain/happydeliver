import type { CreateClientConfig } from "./api/client.gen";

export class NotAuthorizedError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "NotAuthorizedError";
    }
}

async function customFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const response = await fetch(input, init);

    if (response.status === 400) {
        const json = await response.json();
        if (
            json.error ==
            "error in openapi3filter.SecurityRequirementsError: security requirements failed: invalid session"
        ) {
            throw new NotAuthorizedError(json.error.substring(80));
        }
    }

    return response;
}

export const createClientConfig: CreateClientConfig = (config) => ({
    ...config,
    baseUrl: "/api/",
    fetch: customFetch,
});
