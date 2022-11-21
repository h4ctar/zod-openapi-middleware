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
        "/hello/world/{world}": {
            summary: "Hello World Path",
            description: "Long description of the hello world path",
            // The parameters can be defined here for the path, or in each operation
            // We only support text/plain
            parameters: [
                {
                    name: "hello",
                    in: "query",
                    required: true,
                },
                {
                    name: "world",
                    in: "path",
                    required: true,
                },
            ],
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

// Add an operation
app.post(
    "/hello/world/:world",
    operation({
        // This path needs to match the path route
        _path: "/hello/world/{world}",
        // This method needs to match the method that the route is added with
        _method: OpenAPIV3.HttpMethods.POST,
        summary: "Test Hello World Operation",
        description: "A long description of the test world hello operation",
        // This request body zod schema will be converted to an OpenAPI schema by zod-to-json-schema and overwrite any requestBody schema
        requestBody: {
            description: "The body for the request",
            content: {
                "application/json": {
                    _schema: User,
                },
            },
        },
        responses: {
            "200": {
                description: "Success!",
                content: {
                    "application/json": {
                        _schema: User,
                    },
                },
            },
        },
        // The scopes defined in this security requirement will be checked by the middleware
        security: [{
            auth: ["admin"]
        }],
    }, spec),
    (req, res) => res.send(req.body),
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
