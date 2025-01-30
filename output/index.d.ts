import "reflect-metadata";
import { AppContext, AppPlugin } from "@tsdiapi/server";
import { ValidateSessionFunction } from "./jwt-auth";
export { jwt, JWTGuard, ValidateSessionFunction, CurrentSession, JWTTokenAuthCheckHandler } from "./jwt-auth";
declare const SignJWT: any;
declare const VerifyJWT: any;
export { SignJWT, VerifyJWT };
export type PluginOptions<TGuards extends Record<string, ValidateSessionFunction<any>> = {}> = {
    secretKey?: string;
    expirationTime?: number;
    guards?: TGuards;
};
declare class App implements AppPlugin {
    name: string;
    config: PluginOptions;
    context: AppContext;
    constructor(config?: PluginOptions);
    onInit(ctx: AppContext): Promise<void>;
}
export default function createPlugin(config?: PluginOptions): App;
//# sourceMappingURL=index.d.ts.map