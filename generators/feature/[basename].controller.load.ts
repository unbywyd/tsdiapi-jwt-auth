import { Container } from "typedi";
import { AppContext, buildExtraResponseCodes, response200, response400, response401 } from "@tsdiapi/server";
import {{className}}Service, {
  InputOtpVerifySchema,
  Output{{pascalCase userModelName}}SignInSchema,
  Output{{pascalCase userModelName}}AuthSchema,
  Input{{pascalCase userModelName}}SignInSchema,
  InputAdminSignUpSchema,
  InputAdminSignInSchema,
  OutputAdminAuthSchema,
  AuthSession,
  Output{{pascalCase userModelName}}SchemaLiteWithoutPassword,
  OutputAdminSchemaLiteWithoutPassword
} from "./{{kebabCase name}}.service.js";
import { HybridAuthGuard, useSession } from "@tsdiapi/jwt-auth";

export default function controllers({ useRoute }: AppContext) {
  const service = Container.get({{className}}Service);

  useRoute('auth')
    .post("/sign-in")
    .summary("SignIn")
    .body(Input{{pascalCase userModelName}}SignInSchema)
    .codes(buildExtraResponseCodes(Output{{pascalCase userModelName}}SignInSchema))
    .handler(async (req) => {
      const result = await service.signIn(req.body);
      return response200(result);
    })
    .build();

  useRoute('auth')
    .post("/verify")
    .summary("Verify Code")
    .body(InputOtpVerifySchema)
    .codes(buildExtraResponseCodes(Output{{pascalCase userModelName}}AuthSchema))
    .handler(async (req) => {
      const result = await service.verify(req.body);
      return response200(result);
    })
    .build();

  useRoute('auth')
    .get("/me")
    .summary("Get Current {{pascalCase userModelName}}")
    .codes(buildExtraResponseCodes(Output{{pascalCase userModelName}}SchemaLiteWithoutPassword))
    .auth('bearer')
    .guard(HybridAuthGuard())
    .description("Get information about the currently authenticated user")
    .handler(async (req) => {
      const session = useSession<AuthSession>(req);
      const result = await service.getCurrent{{pascalCase userModelName}}(session as AuthSession);
      return response200(result);
    })
    .build();

  useRoute('admin')
    .post("/auth/register")
    .summary("Admin Registration")
    .body(InputAdminSignUpSchema)
    .codes(buildExtraResponseCodes(OutputAdminAuthSchema))
    .handler(async (req) => {
      const result = await service.signUpAdmin(req.body);
      return response200(result);
    })
    .build();

  useRoute('admin')
    .post("/auth/sign-in")
    .summary("Admin SignIn")
    .body(InputAdminSignInSchema)
    .codes(buildExtraResponseCodes(OutputAdminAuthSchema))
    .handler(async (req) => {
      const result = await service.signInByAdmin(req.body);
      return response200(result);
    })
    .build();

  useRoute('admin')
    .post("/auth/verify")
    .summary("Admin Verify")
    .body(InputOtpVerifySchema)
    .codes(buildExtraResponseCodes(OutputAdminAuthSchema))
    .handler(async (req) => {
      const result = await service.adminVerify(req.body);
      return response200(result);
    })
    .build();

  useRoute('admin')
    .get("/auth/me")
    .summary("Admin Me")
    .auth("bearer")
    .codes(buildExtraResponseCodes(OutputAdminSchemaLiteWithoutPassword))
    .guard(HybridAuthGuard({
      guardName: "admin"
    }))
    .handler(async (req) => {
      const session = useSession<AuthSession>(req);
      const result = await service.getCurrentAdmin(session as AuthSession);
      return response200(result);
    })
    .build();
}