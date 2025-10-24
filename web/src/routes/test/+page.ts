import { error, redirect, type Load } from "@sveltejs/kit";

import { createTest as apiCreateTest } from "$lib/api";

export const prerender = false;
export const ssr = false;

export const load: Load = async ({}) => {
    let response;
    try {
        response = await apiCreateTest();
    } catch (err) {
        const errorObj = err as { response?: { status?: number }; message?: string };
        error(errorObj.response?.status || 500, errorObj.message || "Unknown error");
    }

    if (response.response.ok && response.data) {
        redirect(302, `/test/${response.data.id}`);
    } else {
        error(response.response.status, response.error);
    }
};
