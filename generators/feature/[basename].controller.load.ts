import { Container } from "typedi";
import { AppContext } from "@tsdiapi/server";
import {{className}}Service, {
  SignInEmailDTO,
  SignInPhoneDTO,
  InputVerifyDTO,
  OutputSignInEmailDTO,
  OutputSignInPhoneDTO,
  OutputVerifyDTO,
} from "./{{kebabCase name}}.service.js";

export default function controllers({ useRoute }: AppContext) {
  const service = Container.get({{className}}Service);

  useRoute()
    .post("/{{kebabCase name}}/email-sign-in")
    .tags(["{{kebabCase name}}"])
    .summary("SignIn By Email")
    .description("Sign in user using email and code")
    .body(SignInEmailDTO)
    .code(200, OutputSignInEmailDTO)
    .handler(async (req) => {
      const result = await service.signInByEmail(req.body);
      return {
        status: 200,
        data: result
      };
    })
    .build();

  useRoute()
    .post("/{{kebabCase name}}/phone-sign-in")
    .tags(["{{kebabCase name}}"])
    .summary("SignIn By Phone")
    .description("Sign in user using phone and code")
    .body(SignInPhoneDTO)
    .code(200, OutputSignInPhoneDTO)
    .handler(async (req) => {
      const result = await service.signInByPhone(req.body);
      return {
        status: 200,
        data: result
      };
    })
    .build();

  useRoute()
    .post("/{{kebabCase name}}/verify")
    .tags(["{{kebabCase name}}"])
    .summary("Verify Code")
    .description("Verify the provided code")
    .body(InputVerifyDTO)
    .code(200, OutputVerifyDTO)
    .handler(async (req) => {
      const result = await service.verify(req.body);
      return {
        status: 200,
        data: result
      };
    })
    .build();
}
