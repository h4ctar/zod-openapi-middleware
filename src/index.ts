import express, { json, NextFunction, Request, Response } from "express";
import { OpenAPIV3 } from "openapi-types";
import redoc from "redoc-express";
import { z } from "zod";
import { operation } from "./spec";

const User = z.object({
    name: z.string()
        .describe("Name of user"),
})
    .describe("User model");

const spec: OpenAPIV3.Document = {
    openapi: "3.0.0",
    info: {
        title: "Test API",
        version: "1.0.0",
    },
    paths: {
        "/hello": {
            summary: "Hello Path",
            description: "Long description of the hello path",
        },
        "/world": {
            summary: "World Path",
            description: "Long description of the world path",
        },
    },
    components: {
        securitySchemes: {
            auth: {
                type: "http",
                scheme: "bearer",
            },
        },
    },
};

const app = express();

app.use(json());

app.get(
    "/hello",
    operation({
        path: "/hello",
        method: OpenAPIV3.HttpMethods.GET,
        operation: {
            summary: "Test Hello Operation",
            description: "A long description of the test hello operation",
            responses: {},
        },
    }, spec),
    (_req, res) => {
        res.send("Hello World");
    },
);

app.post(
    "/world",
    operation({
        path: "/world",
        method: OpenAPIV3.HttpMethods.POST,
        reqBodySchema: User,
        operation: {
            summary: "Test World Operation",
            description: "A long description of the test world operation",
            requestBody: {
                description: "The user for the request",
                content: {},
            },
            responses: {},
            security: [{
                auth: ["admin"]
            }],
        },
    }, spec),
    (_req, res) => {
        res.send("Hello World");
    },
);

app.get("/docs/openapi.json", (_req, res) => res.send(spec));
app.get("/docs", redoc({ title: "API Docs", specUrl: "/docs/openapi.json" }));

app.use((_req, res, _next) => res.status(404).send("Sorry can't find that!"));

app.use((err: any, _req: Request, res: Response, _next: NextFunction) => res.status(500).send(err.message));

app.listen(3000);
