import axios from "axios";

const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

export const axiosInstance = axios.create({
  baseURL: BASE_URL,
  withCredentials: true, // Ensures cookies (JWT) are sent with requests
});
