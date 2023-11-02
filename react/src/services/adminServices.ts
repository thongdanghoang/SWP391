import { UserSystem } from '../model/UserModal';
import {API_URL} from '../utils/constants'

export async function getAllUserSystemService() {
    try {
        const response = await fetch(
            `${API_URL}/admin/all`,
            {
                method: "GET",
                credentials: "include",
            }
        );
        const data = await response.json();
        return data;
    } catch (e) {
        console.log(e);
    }
    return null;
}

export async function getUserSystemService(username : string) {
    try {
        const response = await fetch(
            `${API_URL}/admin/${username}`,
            {
                method: "GET",
                credentials: "include",
            }
        );
        const data = await response.json();
        return data;
    } catch (e) {
        console.log(e);
    }
    return null;
}

export async function deleteUserSystemService(username : string) {
    try {
        const response = await fetch(
            `${API_URL}/admin/${username}`,
            {
                method: "DELETE",
                credentials: "include",
            }
        );
        const data = await response.json();
        return data;
    } catch (e) {
        console.log(e);
    }
    return null;
}

export async function createUserSystemService(newUserSys : UserSystem) {
    try {
        const response = await fetch(
            `${API_URL}/admin`,
            {
                method: "POST",
                credentials: "include",
                body: JSON.stringify(newUserSys)
            }
        );
        const data = await response.json();
        return data;
    } catch (e) {
        console.log(e);
    }
    return null;
}

export async function editUserSystemService(updatedUserSys : UserSystem) {
    try {
        const response = await fetch(
            `${API_URL}/admin`,
            {
                method: "PUT",
                credentials: "include",
                body : JSON.stringify(updatedUserSys)
            }
        );
        const data = await response.json();
        return data;
    } catch (e) {
        console.log(e);
    }
    return null;
}