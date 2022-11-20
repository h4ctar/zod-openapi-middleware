import { expect } from "chai";
import { NextFunction, Request, Response } from "express";
import { OpenAPIV3 } from "openapi-types";
import { z } from "zod";
import { operation } from "./spec";

const User = z.object({
    name: z.string()
        .describe("Name of user"),
})
    .describe("User model");

const DEFAULT_SPEC: OpenAPIV3.Document = {
    openapi: "3.0.0",
    info: {
        title: "Test API",
        version: "1.0.0",
    },
    paths: {},
    components: {
        securitySchemes: {
            auth: {
                type: "http",
                scheme: "bearer",
            },
        },
    },
};

describe("spec middleware", () => {
    describe("openapi builder", () => {
        it("should add the operation to the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/hello": {},
                },
            };

            operation({
                path: "/hello",
                method: OpenAPIV3.HttpMethods.GET,
                operation: {
                    summary: "Test Hello Operation",
                    responses: {},
                },
            }, spec);

            expect(spec.paths["/hello"]?.get).to.exist;
            expect(spec.paths["/hello"]?.get?.summary).to.equal("Test Hello Operation");
        });

        it("should throw an error if path is not defined in the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {},
            };

            expect(() => operation({
                path: "/hello",
                method: OpenAPIV3.HttpMethods.GET,
                operation: {
                    responses: {},
                },
            }, spec)).to.throw("No path object in spec for /hello");
        });

        it("should throw an error if the operation path/method combination already exists", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/hello": {
                        get: {
                            responses: {},
                        },
                    },
                },
            };

            expect(() => operation({
                path: "/hello",
                method: OpenAPIV3.HttpMethods.GET,
                operation: {
                    responses: {},
                },
            }, spec)).to.throw("Can't add get operation to /hello as it is already declared");
        });

        it("should overwrite the request body schema with one generated from the passed zod schema", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/hello": {},
                },
            };

            operation({
                path: "/hello",
                method: OpenAPIV3.HttpMethods.GET,
                reqBodySchema: User,
                operation: {
                    responses: {},
                },
            }, spec);

            const requestBody = spec.paths["/hello"]?.get?.requestBody as OpenAPIV3.RequestBodyObject;
            expect(requestBody).to.exist;
            expect(requestBody.content["application/json"]).to.exist;
            const schema = requestBody.content["application/json"].schema as OpenAPIV3.SchemaObject;
            expect(schema).to.exist;
            expect(schema.type).to.equal("object");
       });
    });

    describe("validator", () => {
        describe("security", () => {
            it("should pass operations with no security requirements declared", () => {
                const spec: OpenAPIV3.Document = {
                    ...DEFAULT_SPEC,
                    paths: {
                        "/hello": {},
                    },
                };
    
                const middleware = operation({
                    path: "/hello",
                    method: OpenAPIV3.HttpMethods.GET,
                    operation: {
                        responses: {},
                    },
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                };
                let nextCalled = false;
                const next: NextFunction = () => { nextCalled = true};

                middleware(req as Request, {} as Response, next);
                expect(nextCalled).to.be.true;
            });

            it("should respond with 403 if there is no authorization header", () => {
                const spec: OpenAPIV3.Document = {
                    ...DEFAULT_SPEC,
                    paths: {
                        "/hello": {},
                    },
                };
    
                const middleware = operation({
                    path: "/hello",
                    method: OpenAPIV3.HttpMethods.GET,
                    operation: {
                        responses: {},
                        security: [{
                            auth: [],
                        }],
                    },
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {},
                };
                const res = new MockResponse();

                middleware(req as Request, res as unknown as Response, () => {});
                expect(res.code).to.equal(403);
                expect(res.body).to.equal("No valid authorization header");
            });
            
            it("should respond with 403 if there is an invalid authorization header", () => {
                const spec: OpenAPIV3.Document = {
                    ...DEFAULT_SPEC,
                    paths: {
                        "/hello": {},
                    },
                };
    
                const middleware = operation({
                    path: "/hello",
                    method: OpenAPIV3.HttpMethods.GET,
                    operation: {
                        responses: {},
                        security: [{
                            auth: [],
                        }],
                    },
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {
                        authorization: "Bobby asdlfjasdflkj",
                    },
                };
                const res = new MockResponse();

                middleware(req as Request, res as unknown as Response, () => {});
                expect(res.code).to.equal(403);
                expect(res.body).to.equal("No valid authorization header");
            });

            it("should respond with 403 if the token can't be verified/parsed", () => {
                const spec: OpenAPIV3.Document = {
                    ...DEFAULT_SPEC,
                    paths: {
                        "/hello": {},
                    },
                };
    
                const middleware = operation({
                    path: "/hello",
                    method: OpenAPIV3.HttpMethods.GET,
                    operation: {
                        responses: {},
                        security: [{
                            auth: [],
                        }],
                    },
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {
                        authorization: "Bearer asdlfjasdflkj",
                    },
                };
                const res = new MockResponse();

                middleware(req as Request, res as unknown as Response, () => {});
                expect(res.code).to.equal(403);
                expect(res.body).to.equal("jwt malformed");
            });

            it("should respond with 403 if the parsed token does not match the token schema");
            
            it("should respond with 403 if the verified token is missing a required role");
            
            it("should pass if the token verifies and there are no required roles");
            
            it("should pass if the token verifies and has a required role");
        });

        it("should respond with 400 if the request path does not match the spec");
        it("should respond with 400 if the request method does not match the spec");
        it("should respond with 400 if the request query params do not match the spec");
        it("should respond with 400 if the request path params do not match the spec");
        it("should respond with 400 if the request body does not match the spec");
        it("should respond with 400 if the response body does not match the spec");
    });
});

class MockResponse implements Partial<Response> {
    public code = 200;
    public body: any;

    status(code: number): Response {
        this.code = code;
        return this as unknown as Response;
    }

    send(body: any): Response {
        this.body = body;
        return this as unknown as Response;
    }
};
