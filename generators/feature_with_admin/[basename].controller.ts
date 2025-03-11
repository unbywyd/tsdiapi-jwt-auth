import {
    Body,
    JsonController,
    Post,
    Get
} from "routing-controllers";
import { Service } from "typedi";
import { OpenAPI } from "routing-controllers-openapi";
import { SuccessResponse, Summary } from '@tsdiapi/server';
import {{className}}Service, { InputVerifyDTO, OutputSignInEmailDTO, {{pascalCase userModelName}}Session, InputSignUpAdminDTO, InputSignInAdminDTO, OutputAdminSessionDTO, OutputSignInPhoneDTO, OutputVerifyDTO, SignInEmailDTO, SignInPhoneDTO } from "./{{kebabCase name}}.service.js";
import { CurrentSession, JWTGuard } from "@tsdiapi/jwt-auth";
import { client } from "@tsdiapi/prisma";


@Service()
@OpenAPI({
    tags: ["{{kebabCase name}}"],
})
@JsonController("{{kebabCase name}}")
export class {{className}}Controller {
    constructor(public authService: {{className}}Service) { }

    @Summary("SignIn By Email")
    @Post('/email-sign-in')
    @SuccessResponse(OutputSignInEmailDTO)
    async signInByEmail(@Body() data: SignInEmailDTO) {
        return this.authService.signInByEmail(data);
    }

    @Summary("SignIn By Phone")
    @Post('/phone-sign-in')
    @SuccessResponse(OutputSignInPhoneDTO)
    async signInByPhone(@Body() data: SignInPhoneDTO) {
        return this.authService.signInByPhone(data);
    }

    @Summary("Verify Code")
    @Post('/verify')
    @SuccessResponse(OutputVerifyDTO)
    async verify(@Body() data: InputVerifyDTO) {
        return this.authService.verify(data);
    }

    @Summary("Admin Registration")
    @Post('/admin/register')
    @SuccessResponse(OutputAdminSessionDTO)
    async adminRegister(@Body() data: InputSignUpAdminDTO) {
        return this.authService.signUpAdmin(data);
    }

    @Summary("Admin SignIn")
    @Post('/admin/sign-in')
    @SuccessResponse(OutputAdminSessionDTO)
    async signInByAdmin(@Body() data: InputSignInAdminDTO) {
        return this.authService.signInByAdmin(data);
    }

    @Summary("Admin")
    @Get('/admin')
    @SuccessResponse(OutputAdminSessionDTO)
    @JWTGuard()
    async getAdmin(
        @CurrentSession() session: {{pascalCase userModelName}}Session
    ) {
        return {
            admin: await client.admin.findUnique({
                where: {
                    id: session.adminId
                }
            })
        }
    }

}
 