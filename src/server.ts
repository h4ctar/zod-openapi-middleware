import express, { json, NextFunction, Request, Response } from "express";
import { OpenAPIV3 } from "openapi-types";
import redoc from "redoc-express";
import { z } from "zod";
import { operation } from "./spec";

// Create schemas using zod
export const User = z.object({
    name: z.string().describe("Name of user"),
}).describe("User model");

// Write all the spec except the operations using the openapi-types
// As routes are created they will be added to this object
export const spec: OpenAPIV3.Document = {
    openapi: "3.0.0",
    info: {
        title: "Test API",
        version: "1.0.0",
    },
    // All the paths need to be created up front, we want to do this anyway so they have a nice summary and description
    paths: {
        "/hello": {
            summary: "Hello Path",
            description: "Long description of the hello path",
        },
        "/world": {
            summary: "World Path",
            description: "Long description of the world path",
        },
        "/query": {
            summary: "Query Path",
            description: "Long description of the query path",
            parameters: [{
                name: "hello",
                in: "query",
            }],
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

// Create the express app
const app = express();
app.use(json());

// Add a GET operation
app.get(
    "/hello",
    operation({
        // This path needs to match the path route
        _path: "/hello",
        // This method needs to match the method that the route is added with
        _method: OpenAPIV3.HttpMethods.GET,
        // This is the OpenAPI operation spec
        summary: "Test Hello Operation",
        description: "A long description of the test hello operation",
        responses: {},
    }, spec),
    (_req, res) => res.send("Hello World"),
);

// Add a POST operation with request body schema
app.post(
    "/world",
    operation({
        _path: "/world",
        _method: OpenAPIV3.HttpMethods.POST,
        // This request body zod schema will be converted to an OpenAPI schema by zod-to-json-schema and overwrite any requestBody schema defined below
        summary: "Test World Operation",
        description: "A long description of the test world operation",
        requestBody: {
            description: "The user for the request",
            content: {
                "application/json": {
                    _schema: User,
                },
            },
        },
        responses: {},
        // The scopes defined in this security requirement will be checked by the middleware
        security: [{
            auth: ["admin"]
        }],
    }, spec),
    (_req, res) => res.send("Hello World"),
);

// Add an operation with query params
app.get(
    "/query",
    operation({
        _path: "/query",
        _method: OpenAPIV3.HttpMethods.GET,
        responses: {},
    }, spec),
    (_req, res) => res.send("Hello World"),
);

// Serve the raw OpenAPI json spec
app.get("/docs/openapi.json", (_req, res) => res.send(spec));
// Server a rendererd OpenAPI spec
app.get("/docs", redoc({ title: "API Docs", specUrl: "/docs/openapi.json" }));

// Fallback to a 404 if no route matches
app.use((_req, res, _next) => res.status(404).send("Sorry can't find that!"));

// Unhandled exception handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => res.status(500).send(err.message));

// Start listening
app.listen(3000);
