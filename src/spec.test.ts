import { expect } from "chai";
import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { OpenAPIV3 } from "openapi-types";
import { z } from "zod";
import { KEY_PAIR, operation } from "./spec";

const User = z.object({
    name: z.string().describe("Name of user"),
}).describe("User model");

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
                _path: "/hello",
                _method: OpenAPIV3.HttpMethods.GET,
                summary: "Test Hello Operation",
                responses: {},
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
                _path: "/hello",
                _method: OpenAPIV3.HttpMethods.GET,
                responses: {},
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
                _path: "/hello",
                _method: OpenAPIV3.HttpMethods.GET,
                responses: {},
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
                _path: "/hello",
                _method: OpenAPIV3.HttpMethods.GET,
                requestBody: {
                    content: {
                        "application/json": {
                            _schema: User,
                        },
                    },
                },
                responses: {},
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
                    _path: "/hello",
                    _method: OpenAPIV3.HttpMethods.GET,
                    responses: {},
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                };
                let nextCalled = false;
                const next: NextFunction = () => { nextCalled = true };

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
                    _path: "/hello",
                    _method: OpenAPIV3.HttpMethods.GET,
                    responses: {},
                    security: [{
                        auth: [],
                    }],
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {},
                };
                const res = new MockResponse();

                middleware(req as Request, res as unknown as Response, () => { });
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
                    _path: "/hello",
                    _method: OpenAPIV3.HttpMethods.GET,
                    responses: {},
                    security: [{
                        auth: [],
                    }],
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {
                        authorization: "Bobby asdlfjasdflkj",
                    },
                };
                const res = new MockResponse();

                middleware(req as Request, res as unknown as Response, () => { });
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
                    _path: "/hello",
                    _method: OpenAPIV3.HttpMethods.GET,
                    responses: {},
                    security: [{
                        auth: [],
                    }],
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {
                        authorization: "Bearer asdlfjasdflkj",
                    },
                };
                const res = new MockResponse();

                middleware(req as Request, res as unknown as Response, () => { });
                expect(res.code).to.equal(403);
                expect(res.body).to.equal("jwt malformed");
            });

            it("should respond with 403 if the parsed token does not match the token schema", () => {
                const token = jwt.sign({ wrong: "wrong" }, KEY_PAIR.privateKey, { algorithm: "RS256" });

                const spec: OpenAPIV3.Document = {
                    ...DEFAULT_SPEC,
                    paths: {
                        "/hello": {},
                    },
                };

                const middleware = operation({
                    _path: "/hello",
                    _method: OpenAPIV3.HttpMethods.GET,
                    responses: {},
                    security: [{
                        auth: [],
                    }],
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {
                        authorization: `Bearer ${token}`,
                    },
                };
                const res = new MockResponse();

                middleware(req as Request, res as unknown as Response, () => { });
                expect(res.code).to.equal(403);
                expect(res.body).to.equal("Token does not match the schema");
            });

            it("should respond with 403 if the verified token is missing a required role", () => {
                const token = jwt.sign({ name: "Ben", roles: ["wrong"] }, { key: KEY_PAIR.privateKey, passphrase: "top secret" }, { algorithm: "RS256" });

                const spec: OpenAPIV3.Document = {
                    ...DEFAULT_SPEC,
                    paths: {
                        "/hello": {},
                    },
                };

                const middleware = operation({
                    _path: "/hello",
                    _method: OpenAPIV3.HttpMethods.GET,
                    responses: {},
                    security: [{
                        auth: ["admin"],
                    }],
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {
                        authorization: `Bearer ${token}`,
                    },
                };
                const res = new MockResponse();

                middleware(req as Request, res as unknown as Response, () => { });
                expect(res.code).to.equal(403);
                expect(res.body).to.equal("Token does not have any of the required roles - wrong doesn't contain any of admin");
            });

            it("should pass if the token verifies and there are no required roles", () => {
                const token = jwt.sign({ name: "Ben", roles: [] }, { key: KEY_PAIR.privateKey, passphrase: "top secret" }, { algorithm: "RS256" });

                const spec: OpenAPIV3.Document = {
                    ...DEFAULT_SPEC,
                    paths: {
                        "/hello": {},
                    },
                };

                const middleware = operation({
                    _path: "/hello",
                    _method: OpenAPIV3.HttpMethods.GET,
                    responses: {},
                    security: [{
                        auth: [],
                    }],
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {
                        authorization: `Bearer ${token}`,
                    },
                };
                let nextCalled = false;
                const next: NextFunction = () => { nextCalled = true };

                middleware(req as Request, {} as Response, next);
                expect(nextCalled).to.be.true;
            });

            it("should pass if the token verifies and has a required role", () => {
                const token = jwt.sign({ name: "Ben", roles: ["admin"] }, { key: KEY_PAIR.privateKey, passphrase: "top secret" }, { algorithm: "RS256" });

                const spec: OpenAPIV3.Document = {
                    ...DEFAULT_SPEC,
                    paths: {
                        "/hello": {},
                    },
                };

                const middleware = operation({
                    _path: "/hello",
                    _method: OpenAPIV3.HttpMethods.GET,
                    responses: {},
                    security: [{
                        auth: ["admin"],
                    }],
                }, spec);

                const req: Partial<Request> = {
                    path: "/hello",
                    method: "GET",
                    headers: {
                        authorization: `Bearer ${token}`,
                    },
                };
                let nextCalled = false;
                const next: NextFunction = () => { nextCalled = true };

                middleware(req as Request, {} as unknown as Response, next);
                expect(nextCalled).to.be.true;
            });
        });

        it("should respond with 400 if the request path does not match the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/hello": {},
                },
            };

            const middleware = operation({
                _path: "/hello",
                _method: OpenAPIV3.HttpMethods.GET,
                responses: {},
            }, spec);

            const req: Partial<Request> = {
                path: "/wrong",
                method: "GET",
            };
            const res = new MockResponse();

            middleware(req as Request, res as unknown as Response, () => { });
            expect(res.code).to.equal(400);
            expect(res.body).to.equal("Request path does not match - /wrong != /hello");
        });

        it("should respond with 400 if the request method does not match the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/hello": {},
                },
            };

            const middleware = operation({
                _path: "/hello",
                _method: OpenAPIV3.HttpMethods.GET,
                responses: {},
            }, spec);

            const req: Partial<Request> = {
                path: "/hello",
                method: "PUT",
            };
            const res = new MockResponse();

            middleware(req as Request, res as unknown as Response, () => { });
            expect(res.code).to.equal(400);
            expect(res.body).to.equal("Request method does not match - PUT != get");
        });

        it("should respond with 400 if the request query params do not match the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/query": {
                        parameters: [{
                            name: "param",
                            in: "query",
                            required: true,
                        }],
                    },
                },
            };

            const middleware = operation({
                _path: "/query",
                _method: OpenAPIV3.HttpMethods.GET,
                responses: {},
            }, spec);

            const req: Partial<Request> = {
                path: "/query",
                method: "GET",
            };
            const res = new MockResponse();

            middleware(req as Request, res as unknown as Response, () => { });
            expect(res.code).to.equal(400);
            expect(res.body).to.equal("Required query parameter param is missing");
        });

        it("should pass if the request query params match the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/query": {
                        parameters: [{
                            name: "param",
                            in: "query",
                            required: true,
                        }],
                    },
                },
            };

            const middleware = operation({
                _path: "/query",
                _method: OpenAPIV3.HttpMethods.GET,
                responses: {},
            }, spec);

            const req: Partial<Request> = {
                path: "/query",
                query: {
                    param: "Ben",
                },
                method: "GET",
            };
            let nextCalled = false;
            const next: NextFunction = () => { nextCalled = true };

            middleware(req as Request, {} as Response, next);
            expect(nextCalled).to.be.true;
        });

        it("should respond with 400 if the request path params do not match the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/users/{userId}": {
                        parameters: [{
                            name: "userId",
                            in: "path",
                            required: true,
                        }],
                    },
                },
            };

            const middleware = operation({
                _path: "/users/{userId}",
                _method: OpenAPIV3.HttpMethods.GET,
                responses: {},
            }, spec);

            const req: Partial<Request> = {
                path: "/users/",
                method: "GET",
            };
            const res = new MockResponse();

            middleware(req as Request, res as unknown as Response, () => { });
            expect(res.code).to.equal(400);
            expect(res.body).to.equal("Required path parameter userId is missing");
        });

        it("should pass if the request path params match the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/users/{userId}": {
                        parameters: [{
                            name: "userId",
                            in: "path",
                            required: true,
                        }],
                    },
                },
            };

            const middleware = operation({
                _path: "/users/{userId}",
                _method: OpenAPIV3.HttpMethods.GET,
                responses: {},
            }, spec);

            const req: Partial<Request> = {
                path: "/users/Ben",
                method: "GET",
                params: {
                    userId: "Ben",
                },
            };
            let nextCalled = false;
            const next: NextFunction = () => { nextCalled = true };

            middleware(req as Request, {} as Response, next);
            expect(nextCalled).to.be.true;
        });

        it("should respond with 400 if the request body does not match the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/hello": {},
                },
            };

            const middleware = operation({
                _path: "/hello",
                _method: OpenAPIV3.HttpMethods.POST,
                requestBody: {
                    content: {
                        "application/json": {
                            _schema: User,
                        },
                    },
                },
                responses: {},
            }, spec);

            const req: Partial<Request> = {
                path: "/hello",
                method: "POST",
                body: { wrong: "Ben" },
            };
            const res = new MockResponse();

            middleware(req as Request, res as unknown as Response, () => { });
            expect(res.code).to.equal(400);
            expect(res.body).to.equal("Request body does not match the schema");
        });

        it("should pass if the request body does match the spec", () => {
            const spec: OpenAPIV3.Document = {
                ...DEFAULT_SPEC,
                paths: {
                    "/hello": {},
                },
            };

            const middleware = operation({
                _path: "/hello",
                _method: OpenAPIV3.HttpMethods.POST,
                requestBody: {
                    content: {
                        "application/json": {
                            _schema: User,
                        },
                    },
                },
                responses: {},
            }, spec);

            const req: Partial<Request> = {
                path: "/hello",
                method: "POST",
                body: { name: "Ben" },
            };
            let nextCalled = false;
            const next: NextFunction = () => { nextCalled = true };

            middleware(req as Request, {} as Response, next);
            expect(nextCalled).to.be.true;
        });

        it("should respond with 400 if the response body does not match the spec");

        it("should pass if the response body does match the spec");
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
