import { Container } from "typedi";
import { AppContext } from "@tsdiapi/server";
import {{className}}Service, {
  InputVerifyDTO,
  OutputSignInEmailDTO,
  OutputSignInPhoneDTO,
  OutputVerifyDTO,
  SignInEmailDTO,
  SignInPhoneDTO,
  InputSignUpAdminDTO,
  InputSignInAdminDTO,
  OutputAdminSessionDTO,
  {{pascalCase userModelName}}Session
} from "./{{kebabCase name}}.service.js";
import { client } from "@tsdiapi/prisma";
import { JWTGuard } from "@tsdiapi/jwt-auth";

export default function controllers(ctx: AppContext) {
  const service = Container.get({{className}}Service);

  ctx.useRoute()
    .post("/{{kebabCase name}}/email-sign-in")
    .tags(["{{kebabCase name}}"])
    .summary("SignIn By Email")
    .body(SignInEmailDTO)
    .code(200, OutputSignInEmailDTO)
    .handler(async (req) => {
      const result = await service.signInByEmail(req.body);
      return { status: 200, data: result };
    })
    .build();

  ctx.useRoute()
    .post("/{{kebabCase name}}/phone-sign-in")
    .tags(["{{kebabCase name}}"])
    .summary("SignIn By Phone")
    .body(SignInPhoneDTO)
    .code(200, OutputSignInPhoneDTO)
    .handler(async (req) => {
      const result = await service.signInByPhone(req.body);
      return { status: 200, data: result };
    })
    .build();

  ctx.useRoute()
    .post("/{{kebabCase name}}/verify")
    .tags(["{{kebabCase name}}"])
    .summary("Verify Code")
    .body(InputVerifyDTO)
    .code(200, OutputVerifyDTO)
    .handler(async (req) => {
      const result = await service.verify(req.body);
      return { status: 200, data: result };
    })
    .build();

  ctx.useRoute()
    .post("/{{kebabCase name}}/admin/register")
    .tags(["{{kebabCase name}}"])
    .summary("Admin Registration")
    .body(InputSignUpAdminDTO)
    .code(200, OutputAdminSessionDTO)
    .handler(async (req) => {
      const result = await service.signUpAdmin(req.body);
      return { status: 200, data: result };
    })
    .build();

  ctx.useRoute()
    .post("/{{kebabCase name}}/admin/sign-in")
    .tags(["{{kebabCase name}}"])
    .summary("Admin SignIn")
    .body(InputSignInAdminDTO)
    .code(200, OutputAdminSessionDTO)
    .handler(async (req) => {
      const result = await service.signInByAdmin(req.body);
      return { status: 200, data: result };
    })
    .build();

  ctx.useRoute()
    .get("/{{kebabCase name}}/admin")
    .tags(["{{kebabCase name}}"])
    .summary("Admin")
    .auth("bearer")
    .guard(JWTGuard())
    .code(200, OutputAdminSessionDTO)
    .handler(async (req) => {
      const session = req.session as {{pascalCase userModelName}}Session;
      const admin = await client.admin.findUnique({
        where: { id: session.adminId }
      });
      return { status: 200, data: admin };
    })
    .build();
}