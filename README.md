# zod OpenAPI middleware

![Build](https://github.com/h4ctar/zod-openapi-middleware/actions/workflows/build.yml/badge.svg)

Express middleware that validates a request using zod and generates an OpenAPI spec.

## Basic usage

Copy the `src/spec.ts` into your project and customise it.

Look at `src/server.ts` for an example of how to use it.

`operation` is a higher order function that takes in the configuration of the operation, it adds the operation to the OpenAPI spec document and returns a middleware that validates and authorises the request.

The OpenAPI spec document can then be served raw or rendered using Redoc or SwaggerUI.

The security is HTTP bearer auth but this can be changed to suit your needs.

All the paths need to be added to the initial OpenAPI spec document.

If a zod request body schema is passed to the `operation` function it'll assume you only want to accept `application/json`.
