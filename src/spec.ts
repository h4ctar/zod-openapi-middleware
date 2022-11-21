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
type OperationConfig<ReqBody = any> = Omit<OpenAPIV3.OperationObject, "requestBody"> & {
    _path: string;
    _method: OpenAPIV3.HttpMethods;
    requestBody?: Omit<OpenAPIV3.RequestBodyObject, "content"> & {
        content: {
            "application/json": OpenAPIV3.MediaTypeObject & {
                _schema?: ZodSchema<ReqBody>;
            };
        };
    };
};

// The schema of the JWTs
const Token = z.object({
    name: z.string(),
    roles: z.string().array(),
});

// The operation higher order function that returns an Express middleware
// Adds the operation to the OpenAPI spec
// The resulting middleware checks the security requirements and the rest of the request
export const operation = <ReqBody = any>(operationConfig: OperationConfig<ReqBody>, spec: OpenAPIV3.Document): RequestHandler<any, any, ReqBody> => {
    addOperationToSpec(operationConfig, spec);

    return (req: Request, res: Response, next: NextFunction) => {
        try {
            checkSecurity(req, operationConfig, spec);
        } catch (err: any) {
            res.status(403).send(err.message);
            return;
        }

        try {
            checkPath(req, operationConfig);
            checkMethod(req, operationConfig);
            checkParams("path", req, operationConfig, spec);
            checkParams("query", req, operationConfig, spec);
            checkAndParseRequestBody(req, operationConfig);
        } catch (err: any) {
            res.status(400).send(err.message);
            return;
        }

        next();
    };
};

const addOperationToSpec = (operationConfig: OperationConfig, spec: OpenAPIV3.Document) => {
    const pathObject = spec.paths[operationConfig._path];
    if (!pathObject) {
        throw new Error(`No path object in spec for ${operationConfig._path}`);
    }

    if (pathObject[operationConfig._method]) {
        throw new Error(`Can't add ${operationConfig._method} operation to ${operationConfig._path} as it is already declared`);
    }

    // Add request body schema
    const schema = operationConfig.requestBody?.content["application/json"]?._schema;
    if (schema) {
        operationConfig.requestBody!.content["application/json"]!.schema = convertSchema(schema);
    }

    pathObject[operationConfig._method] = operationConfig;
};

const checkSecurity = (req: Request, operationConfig: OperationConfig, spec: OpenAPIV3.Document) => {
    const security = operationConfig.security || spec.security;
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
        const parseResult = Token.safeParse(jwt.verify(token, KEY_PAIR.publicKey, { algorithms: ["RS256"] }));

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

const checkPath = (req: Request, operationConfig: OperationConfig) => {
    if (!req.path.match(operationConfig._path.replace(/{.*}/g, "(.*)"))) {
        throw new Error(`Request path does not match - ${req.path} != ${operationConfig._path}`);
    }
};

const checkMethod = (req: Request, operationConfig: OperationConfig) => {
    if (req.method.toLowerCase() !== operationConfig._method) {
        throw new Error(`Request method does not match - ${req.method} != ${operationConfig._method}`);
    }
};

const checkParams = (location: "path" | "query", req: Request, operationConfig: OperationConfig, spec: OpenAPIV3.Document) => {
    const pathEntry = Object.entries(spec.paths)
        .find((pathEntry) => req.path.match(pathEntry[0].replace(/{.*}/g, "(.*)")));
    if (!pathEntry || !pathEntry[1]) {
        throw new Error(`Path object could not be found for ${req.path}`);
    }
    const path = pathEntry[1];

    const parameters = [
        ...(path.parameters || []),
        ...(operationConfig.parameters || []),
    ] as OpenAPIV3.ParameterObject[];
    parameters
        .filter((parameter) => parameter.in === location)
        .filter((parameter) => parameter.required)
        .forEach((parameter) => {
            if (!req.params || !req.params[parameter.name]) {
                throw new Error(`Required ${location} parameter ${parameter.name} is missing`);
            }
        });
};

const checkAndParseRequestBody = (req: Request, operationConfig: OperationConfig) => {
    const schema = operationConfig.requestBody?.content["application/json"]?._schema;
    if (schema) {
        const parseResult = schema.safeParse(req.body);
        if (parseResult.success) {
            req.body = parseResult.data;
        } else {
            throw new Error("Request body does not match the schema");
        }
    }
};

const convertSchema = (zodSchema: ZodSchema) =>
    zodToJsonSchema(zodSchema, { $refStrategy: "none", target: "openApi3" }) as OpenAPIV3.SchemaObject;
