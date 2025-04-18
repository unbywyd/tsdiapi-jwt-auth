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
  ErrorResponseDTO,
  OutputAdminDTO,
  {{pascalCase userModelName}}Session,
  Output{{pascalCase userModelName}}DTO
} from "./{{kebabCase name}}.service.js";
import { client } from "@tsdiapi/prisma";
import { JWTGuard, isBearerValid } from "@tsdiapi/jwt-auth";

export default function controllers({useRoute}: AppContext) {
  const service = Container.get({{className}}Service);

  useRoute('{{kebabCase name}}')
    .post("/email-sign-in")
    .summary("SignIn By Email")
    .body(SignInEmailDTO)
    .code(200, OutputSignInEmailDTO)
    .code(400, ErrorResponseDTO)
    .handler(async (req) => {
      try {
        const result = await service.signInByEmail(req.body);
        return { status: 200, data: result };
      } catch (error) {
        return {
          status: 400,
          data: { message: error.message }
        };
      }
    })
    .build();

  useRoute('{{kebabCase name}}')
    .post("/phone-sign-in")
    .summary("SignIn By Phone")
    .body(SignInPhoneDTO)
    .code(200, OutputSignInPhoneDTO)
    .code(400, ErrorResponseDTO)
    .handler(async (req) => {
        try {
          const result = await service.signInByPhone(req.body);
          return { status: 200, data: result };
        } catch (error) {
          return {
            status: 400,
            data: { message: error.message }
          };
        }
    })
    .build();

  useRoute('{{kebabCase name}}')
    .post("/verify")
    .summary("Verify Code")
    .body(InputVerifyDTO)
    .code(200, OutputVerifyDTO)
    .code(400, ErrorResponseDTO)
    .handler(async (req) => {
      try {
        const result = await service.verify(req.body);
        return { status: 200, data: result };
      } catch (error) {
        return {
          status: 400,
          data: { message: error.message }
        };
      }
    })
    .build();

    useRoute('auth')
    .get("/me")
    .summary("Get Current User")
    .code(401, ErrorResponseDTO)
    
    .auth('bearer', async (req, reply) => {
      const isValid = await isBearerValid(req);
      if (!isValid) {
        return {
          status: 401,
          data: { message: 'Invalid access token' }
        };
      }
      return true;
    })
    .description("Get information about the currently authenticated user")
    .code(200, Output{{pascalCase userModelName}}DTO)
    .handler(async (req) => {
      const session = req.session;
      console.log(session);
      try {
        const result = await service.getCurrentUser(session as {{pascalCase userModelName}}Session);
        return {
          status: 200,
          data: result
        };
      } catch (error) {
        return {
          status: 401,
          data: { message: error.message }
        };
      }
    })
    .build();

  useRoute('{{kebabCase name}}')
    .post("/admin/register")
    .summary("Admin Registration")
    .body(InputSignUpAdminDTO)
    .code(200, OutputAdminSessionDTO)
    .code(400, ErrorResponseDTO)
    .handler(async (req) => {
      try {
        const result = await service.signUpAdmin(req.body);
        return { status: 200, data: result };
      } catch (error) {
        return {
          status: 400,
          data: { message: error.message }
        };
      }
    })
    .build();

  useRoute('{{kebabCase name}}')
    .post("/admin/sign-in")
    .summary("Admin SignIn")
    .body(InputSignInAdminDTO)
    .code(200, OutputAdminSessionDTO)
    .code(400, ErrorResponseDTO)
    .handler(async (req) => {
      try {
        const result = await service.signInByAdmin(req.body);
        return { status: 200, data: result };
      } catch (error) {
        return {
          status: 400,
          data: { message: error.message }
        };
      }
    })
    .build();

  useRoute('{{kebabCase name}}')
    .get("/admin")
    .summary("Admin")
    .auth("bearer")
    .code(403, ErrorResponseDTO)
    .code(200, OutputAdminDTO)
    .code(400, ErrorResponseDTO)
    .guard(JWTGuard())
    .handler(async (req) => {
      try {
        const session = req.session as {{pascalCase userModelName}}Session;
        const admin = await client.admin.findUnique({
          where: { id: session.adminId }
        });
        return { status: 200, data: admin };
      } catch (error) {
        return {
          status: 400,
          data: { message: error.message }
        };
      }
    })
    .build();
}