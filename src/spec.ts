import { NextFunction, Request, RequestHandler, Response } from "express";
import { OpenAPIV3 } from "openapi-types";
import { z, ZodSchema } from "zod";
import jwt from "jsonwebtoken";
import zodToJsonSchema from "zod-to-json-schema";

// Test with https://token.dev/
const SIGNING_KEY = "NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=";

type OperationConfig<ReqBody> = {
    path: string;
    method: OpenAPIV3.HttpMethods;
    reqBodySchema?: ZodSchema<ReqBody>;
    operation: OpenAPIV3.OperationObject;
};

const Token = z.object({
    name: z.string(),
    roles: z.string().array(),
});

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
            checkParams();
            checkQuery();
            checkAndParseRequestBody(req, config);
        } catch (err: any) {
            res.status(400).send(err.message);
            return;
        }

        next();
    };
};

const addOperationToSpec = (config: OperationConfig<any>, spec: OpenAPIV3.Document) => {
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

const checkSecurity = (req: Request, config: OperationConfig<any>, spec: OpenAPIV3.Document) => {
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

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decodedToken = Token.parse(jwt.verify(token, SIGNING_KEY));

        if (requiredRoles.length > 0 && !requiredRoles.some((role) => decodedToken.roles.includes(role))) {
            throw new Error(`Token does not have any of the required roles - ${decodedToken.roles} doesn't contain any of ${requiredRoles}`);
        }
    } else {
        throw new Error("No valid authorization header");
    }
};

const checkPath = (req: Request, config: OperationConfig<any>) => {
    if (req.path !== config.path) {
        throw new Error(`Request path does not match - ${req.path} != ${config.path}`);
    }
};

const checkMethod = (req: Request, config: OperationConfig<any>) => {
    if (req.method.toLowerCase() !== config.method) {
        throw new Error(`Request method does not match - ${req.method} != ${config.method}`);
    }
};

const checkParams = () => {};
const checkQuery = () => {};

const checkAndParseRequestBody = (req: Request, config: OperationConfig<any>) => {
    if (config.reqBodySchema) {
        req.body = config.reqBodySchema.parse(req.body);
    }
};

const convertSchema = (zodSchema: ZodSchema) =>
    zodToJsonSchema(zodSchema, { $refStrategy: "none", target: "openApi3" }) as OpenAPIV3.SchemaObject;
