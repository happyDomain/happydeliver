// The message the API put in an error body, when it put one there.
export function apiMessage(apiError: unknown): string | null {
    return apiError && typeof apiError === "object" && "message" in apiError
        ? String(apiError.message)
        : null;
}
