import { error, redirect, type Load } from "@sveltejs/kit";

import { createTest as apiCreateTest } from "$lib/api";

export const prerender = false;
export const ssr = false;

export const load: Load = async ({}) => {
    let response;
    try {
        response = await apiCreateTest();
    } catch (err) {
        error(err.response.status, err.message);
    }

    if (response.response.ok) {
        redirect(302, `/test/${response.data.id}`);
    } else {
        error(response.response.status, response.error);
    }
};
