import "reflect-metadata";
import { AppContext, AppPlugin } from "@tsdiapi/server";
import { ValidateSessionFunction } from "./jwt-auth.js";
export * from "./jwt-auth.js";
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
export declare function getJWTAuthProvider(): import("./jwt-auth.js").JWTAuthProvider<Record<string, ValidateSessionFunction<any>>>;
//# sourceMappingURL=index.d.ts.map