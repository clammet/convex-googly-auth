import { defineApp } from "convex/server";
import googlyAuth from "@clammet/convex-googly-auth/convex.config.js";

const app = defineApp();
app.use(googlyAuth);

export default app;
