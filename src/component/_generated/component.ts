/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";
import type { api } from "./api.js";

type PublicApi = typeof api;

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    [Module in keyof PublicApi]: {
      [Fn in keyof PublicApi[Module]]: PublicApi[Module][Fn] extends FunctionReference<
        infer FunctionType,
        "public",
        infer Args,
        infer ReturnType
      >
        ? FunctionReference<FunctionType, "internal", Args, ReturnType, Name>
        : never;
    };
  };
