import crypto from "crypto";
import { NextFunction, Request, RequestHandler, Response } from "express";
import jwt from "jsonwebtoken";
import { OpenAPIV3 } from "openapi-types";
import { z, ZodSchema } from "zod";
import zodToJsonSchema from "zod-to-json-schema";

// Generate a key pair to use for signing and verifying the JWTs
// This would usually be done by an OIDC provider, but it's here for testing
export const KEY_PAIR = crypto.generateKeyPairSync("rsa", {
    // RS256 requires a modulus length of at least 2048 bits
    modulusLength: 2048,
    publicKeyEncoding: {
        type: "spki",
        format: "pem",
    },
    privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
    },
});
// Logged so we can test with jwt.io
console.log(KEY_PAIR.publicKey);
console.log(KEY_PAIR.privateKey);

// The operation configuration type
type OperationConfig<ReqBody = any> = {
    path: string;
    method: OpenAPIV3.HttpMethods;
    reqBodySchema?: ZodSchema<ReqBody>;
    operation: OpenAPIV3.OperationObject;
};

// The schema of the JWTs
const Token = z.object({
    name: z.string(),
    roles: z.string().array(),
});

// The operation higher order function that returns an Express middleware
// Adds the operation to the OpenAPI spec
// The resulting middleware checks the security requirements and the rest of the request
export const operation = <ReqBody = any>(config: OperationConfig<ReqBody>, spec: OpenAPIV3.Document): RequestHandler<any, any, ReqBody> => {
    addOperationToSpec(config, spec);

    return (req: Request, res: Response, next: NextFunction) => {
        try {
            checkSecurity(req, config, spec);
        } catch (err: any) {
            res.status(403).send(err.message);
            return;
        }

        try {
            checkPath(req, config);
            checkMethod(req, config);
            checkPathParams();
            checkQueryParams(req);
            checkAndParseRequestBody(req, config);
        } catch (err: any) {
            res.status(400).send(err.message);
            return;
        }

        next();
    };
};

const addOperationToSpec = (config: OperationConfig, spec: OpenAPIV3.Document) => {
    const pathObject = spec.paths[config.path];
    if (!pathObject) {
        throw new Error(`No path object in spec for ${config.path}`);
    }

    if (pathObject[config.method]) {
        throw new Error(`Can't add ${config.method} operation to ${config.path} as it is already declared`);
    }

    // Add request body schema
    if (config.reqBodySchema) {
        config.operation.requestBody = {
            ...config.operation.requestBody,
            content: {
                ...(config.operation.requestBody as OpenAPIV3.RequestBodyObject)?.content,
                "application/json": {
                    schema: convertSchema(config.reqBodySchema),
                },
            },
        };
    }

    pathObject[config.method] = config.operation;
};

const checkSecurity = (req: Request, config: OperationConfig, spec: OpenAPIV3.Document) => {
    const security = config.operation.security || spec.security;
    if (!security) {
        return;
    }

    // Find requirement
    const requirement = security.find((requirement) => requirement.auth);
    if (!requirement) {
        return;
    }

    // Find required roles
    const requiredRoles = requirement.auth;

    // Decode and verify the JWT
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const parseResult = Token.safeParse(jwt.verify(token, KEY_PAIR.publicKey, { algorithms: ["RS256"]}));

        if (parseResult.success) {
            // Check that the JWT has one of the required roles
            if (requiredRoles.length > 0 && !requiredRoles.some((role) => parseResult.data.roles.includes(role))) {
                throw new Error(`Token does not have any of the required roles - ${parseResult.data.roles} doesn't contain any of ${requiredRoles}`);
            }
        } else {
            throw new Error("Token does not match the schema");
        }
    } else {
        throw new Error("No valid authorization header");
    }
};

const checkPath = (req: Request, config: OperationConfig) => {
    if (req.path !== config.path) {
        throw new Error(`Request path does not match - ${req.path} != ${config.path}`);
    }
};

const checkMethod = (req: Request, config: OperationConfig) => {
    if (req.method.toLowerCase() !== config.method) {
        throw new Error(`Request method does not match - ${req.method} != ${config.method}`);
    }
};

const checkPathParams = () => {};

const checkQueryParams = (req: Request, spec: OpenAPIV3.Document) => {
    const pathObject = spec.paths.find
    if 
};

const checkAndParseRequestBody = (req: Request, config: OperationConfig) => {
    if (config.reqBodySchema) {
        const parseResult = config.reqBodySchema.safeParse(req.body);
        if (parseResult.success) {
            req.body = parseResult.data;
        } else {
            throw new Error("Request body does not match the schema");
        }
    }
};

const convertSchema = (zodSchema: ZodSchema) =>
    zodToJsonSchema(zodSchema, { $refStrategy: "none", target: "openApi3" }) as OpenAPIV3.SchemaObject;
