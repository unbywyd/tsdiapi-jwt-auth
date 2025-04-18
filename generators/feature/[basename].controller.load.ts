import { Container } from "typedi";
import { AppContext } from "@tsdiapi/server";
import {{className}}Service, {
  SignInEmailDTO,
  SignInPhoneDTO,
  InputVerifyDTO,
  OutputSignInEmailDTO,
  OutputSignInPhoneDTO,
  OutputVerifyDTO,
  ErrorResponseDTO,
  Output{{pascalCase userModelName}}DTO,
  {{pascalCase userModelName}}Session
} from "./{{kebabCase name}}.service.js";
import { isBearerValid } from "@tsdiapi/jwt-auth";


export default function controllers({ useRoute }: AppContext) {
  const service = Container.get({{className}}Service);

  useRoute('auth')
    .post("/email-sign-in")
    .summary("SignIn By Email")
    .description("Sign in user using email and code")
    .body(SignInEmailDTO)
    .code(200, OutputSignInEmailDTO)
    .code(400, ErrorResponseDTO)
    .handler(async (req) => {
      try {
        const result = await service.signInByEmail(req.body);
        return {
          status: 200,
          data: result
        };
      } catch (error) {
        return {
          status: 400,
          data: { message: error.message }
        };
      }
    })
    .build();

  useRoute('auth')
    .post("/phone-sign-in")
    .summary("SignIn By Phone")
    .description("Sign in user using phone and code")
    .body(SignInPhoneDTO)
    .code(200, OutputSignInPhoneDTO)
    .code(400, ErrorResponseDTO)
    .handler(async (req) => {
      try {
        const result = await service.signInByPhone(req.body);
        return {
          status: 200,
          data: result
        };
      } catch (error) {
        return {
          status: 400,
          data: { message: error.message }
        };
      }
    })
    .build();

  useRoute('auth')
    .post("/verify")
    .summary("Verify Code")
    .description("Verify the provided code")
    .body(InputVerifyDTO)
    .code(200, OutputVerifyDTO)
    .code(400, ErrorResponseDTO)
    .handler(async (req) => {
      try {
        const result = await service.verify(req.body);
        return {
          status: 200,
          data: result
        };
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
}
