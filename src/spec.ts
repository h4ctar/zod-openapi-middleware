import { NextFunction, Request, RequestHandler, Response } from "express";
import { OpenAPIV3 } from "openapi-types";
import { z, ZodSchema } from "zod";
import jwt from "jsonwebtoken";
import zodToJsonSchema from "zod-to-json-schema";

const SIGNING_KEY = "NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=";

type OperationConfig<ReqBody> = {
    path: string;
    method: OpenAPIV3.HttpMethods;
    summary: string;
    description: string;
    reqBody?: {
        description: string;
        schema: ZodSchema<ReqBody>;
    },
    roles: string[];
};

const Token = z.object({
    name: z.string(),
    roles: z.string().array(),
});

export const operation = <ReqBody = any>(config: OperationConfig<ReqBody>, spec: OpenAPIV3.Document): RequestHandler<any, any, ReqBody> => {
    addOperationToSpec(config, spec);

    return (req: Request, res: Response, next: NextFunction) => {
        try {
            checkSecurity(req, config);
        } catch (err: any) {
            res.status(403).send(err.message);
            return;
        }

        try {
            checkPath(req, config);
            checkMethod(req, config);
            checkParams();
            checkQuery();
            checkRequestBody(req, config);
        } catch (err: any) {
            res.status(400).send(err.message);
            return;
        }

        next();
    };
};

const addOperationToSpec = (config: OperationConfig<any>, spec: OpenAPIV3.Document) => {
    // Add operation to the spec
    const pathObject = spec.paths[config.path];
    if (!pathObject) {
        throw new Error(`No path object in spec for ${config.path}`);
    }

    if (pathObject[config.method]) {
        throw new Error(`Can't add ${config.method} operation to ${config.path} as it is already declared`);
    }
    pathObject[config.method] = {
        summary: config.summary,
        description: config.description,
        ...(config.reqBody ? {
            requestBody: {
                description: config.reqBody.description,
                content: {
                    "application/json": {
                        schema: convertSchema(config.reqBody.schema),
                    },
                },
            },
        } : {}),
        responses: {},
        security: [{
            BearerAuth: config.roles,
        }],
    };
};

const checkSecurity = (req: Request, config: OperationConfig<any>) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.split(" ")[1];
        const decodedToken = Token.parse(jwt.verify(token, SIGNING_KEY));
        if (config.roles.length > 0 && !config.roles.some((role) => decodedToken.roles.includes(role))) {
            throw new Error(`Token does not have any of the required roles ${config.roles}`);
        }
    } else {
        throw new Error("No valid authorization header");
    }
};

const checkPath = (req: Request, config: OperationConfig<any>) => {
    if (req.path !== config.path) {
        throw new Error(`Request path does not match ${req.path} != ${config.path}`);
    }
};

const checkMethod = (req: Request, config: OperationConfig<any>) => {
    if (req.method.toLowerCase() !== config.method) {
        throw new Error(`Request method does not match ${req.method} != ${config.method}`);
    }
};

const checkParams = () => {};
const checkQuery = () => {};

const checkRequestBody = (req: Request, config: OperationConfig<any>) => {
    if (config.reqBody) {
        const parsed = config.reqBody.schema.safeParse(req.body);
        if (parsed.success) {
            req.body = parsed.data;
        } else {
            throw new Error(JSON.stringify(parsed.error));
        }
    }
};

const convertSchema = (zodSchema: ZodSchema) =>
    zodToJsonSchema(zodSchema, { $refStrategy: "none", target: "openApi3" }) as OpenAPIV3.SchemaObject;
