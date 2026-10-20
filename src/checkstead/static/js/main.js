// @ts-check
import { client } from "./api.js";
import { createApp } from "./app.js";

const root = document.getElementById("app");
if (root) void createApp({ root, api: client() }).start();
